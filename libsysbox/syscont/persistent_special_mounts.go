//go:build linux
// +build linux

package syscont

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"

	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

const (
	rootfsRwLayerAnnotation      = "sysbox/rootfs-rw-layer"
	kubernetesContainerNameAnno  = "io.kubernetes.cri.container-name"
	kubernetesSandboxUIDAnno     = "io.kubernetes.cri.sandbox-uid"
	rootfsSpecialMountBase       = "/var/lib/sysbox/rootfs-special-volume"
	persistentSpecialMetaVersion = 1
	kubeletPodsDir               = "/var/lib/kubelet/pods"
)

type rootfsRwLayerEntry struct {
	Name       string `json:"name"`
	VolumeName string `json:"volumeName"`
	Path       string `json:"path"`
}

type persistentSpecialMapping struct {
	Name        string `json:"name"`
	Destination string `json:"destination"`
}

type persistentSpecialMeta struct {
	Version  int                        `json:"version"`
	Mappings []persistentSpecialMapping `json:"mappings"`
}

type persistentSpecialConfig struct {
	entry       rootfsRwLayerEntry
	pvcRoot     string
	layerRoot   string
	specialRoot string
	meta        persistentSpecialMeta
}

// cfgPersistentSpecialMounts converts the admission-injected, hidden PVC mount
// into explicit mounts for data that Sysbox otherwise stores in node-local
// special volumes. Containers without a matching rw-layer entry retain the
// legacy behavior.
func cfgPersistentSpecialMounts(spec *specs.Spec) error {
	return cfgPersistentSpecialMountsAt(spec, kubeletPodsDir)
}

func cfgPersistentSpecialMountsAt(spec *specs.Spec, podsDir string) error {
	config, enabled, err := resolvePersistentSpecialConfig(spec, podsDir)
	if err != nil || !enabled {
		return err
	}

	if err := initializePersistentSpecial(spec, config, rsyncPersistentSpecialDir); err != nil {
		return err
	}

	hiddenDest := filepath.Join(rootfsSpecialMountBase, config.entry.VolumeName)
	filtered := make([]specs.Mount, 0, len(spec.Mounts)+len(config.meta.Mappings))
	for _, mount := range spec.Mounts {
		if filepath.Clean(mount.Destination) != hiddenDest {
			filtered = append(filtered, mount)
		}
	}
	for _, mapping := range config.meta.Mappings {
		filtered = append(filtered, specs.Mount{
			Source:      filepath.Join(config.specialRoot, mapping.Name),
			Destination: mapping.Destination,
			Type:        "bind",
			Options:     []string{"rbind", "rprivate"},
		})
	}
	spec.Mounts = filtered
	return nil
}

func resolvePersistentSpecialConfig(spec *specs.Spec, podsDir string) (persistentSpecialConfig, bool, error) {
	raw := spec.Annotations[rootfsRwLayerAnnotation]
	if raw == "" {
		return persistentSpecialConfig{}, false, nil
	}
	containerName := spec.Annotations[kubernetesContainerNameAnno]
	if containerName == "" {
		for _, mount := range spec.Mounts {
			destination := filepath.Clean(mount.Destination)
			if destination == rootfsSpecialMountBase || strings.HasPrefix(destination, rootfsSpecialMountBase+string(filepath.Separator)) {
				return persistentSpecialConfig{}, false, fmt.Errorf("%s is set and a reserved PVC mount exists, but Kubernetes container name annotation is missing", rootfsRwLayerAnnotation)
			}
		}
		// CRI forwards Pod annotations to the sandbox OCI spec, which has no
		// Kubernetes container-name annotation and no app-container mounts.
		return persistentSpecialConfig{}, false, nil
	}

	entries, err := decodeRootfsRwLayerEntries(raw)
	if err != nil {
		return persistentSpecialConfig{}, false, err
	}
	var matching []rootfsRwLayerEntry
	for _, entry := range entries {
		if entry.Name == containerName {
			matching = append(matching, entry)
		}
	}
	if len(matching) == 0 {
		return persistentSpecialConfig{}, false, nil
	}
	if len(matching) != 1 {
		return persistentSpecialConfig{}, false, fmt.Errorf("container %q has %d rootfs rw-layer entries", containerName, len(matching))
	}
	entry := matching[0]
	if entry.VolumeName == "" {
		return persistentSpecialConfig{}, false, fmt.Errorf("container %q rootfs rw-layer volumeName is empty", containerName)
	}
	if filepath.Base(entry.VolumeName) != entry.VolumeName || entry.VolumeName == "." || entry.VolumeName == ".." {
		return persistentSpecialConfig{}, false, fmt.Errorf("container %q rootfs rw-layer volumeName is unsafe", containerName)
	}
	cleanPath, err := cleanRelativeLayerPath(entry.Path)
	if err != nil {
		return persistentSpecialConfig{}, false, fmt.Errorf("container %q rootfs rw-layer path: %w", containerName, err)
	}
	entry.Path = cleanPath

	hiddenDest := filepath.Join(rootfsSpecialMountBase, entry.VolumeName)
	var hidden []specs.Mount
	reservedMountCount := 0
	for _, mount := range spec.Mounts {
		destination := filepath.Clean(mount.Destination)
		if destination == rootfsSpecialMountBase || strings.HasPrefix(destination, rootfsSpecialMountBase+string(filepath.Separator)) {
			reservedMountCount++
		}
		if destination == hiddenDest {
			hidden = append(hidden, mount)
		}
	}
	if len(hidden) == 0 && reservedMountCount == 0 {
		return persistentSpecialConfig{}, false, nil
	}
	if len(hidden) != 1 {
		return persistentSpecialConfig{}, false, fmt.Errorf("container %q requires exactly one hidden PVC mount at %s; found %d", containerName, hiddenDest, len(hidden))
	}
	if hidden[0].Type != "bind" || !filepath.IsAbs(hidden[0].Source) {
		return persistentSpecialConfig{}, false, fmt.Errorf("hidden PVC mount at %s is not an absolute bind mount", hiddenDest)
	}
	podUID := spec.Annotations[kubernetesSandboxUIDAnno]
	if podUID == "" {
		return persistentSpecialConfig{}, false, fmt.Errorf("container %q Kubernetes sandbox UID annotation is missing", containerName)
	}
	if filepath.Base(podUID) != podUID || podUID == "." || podUID == ".." {
		return persistentSpecialConfig{}, false, fmt.Errorf("container %q Kubernetes sandbox UID annotation is unsafe", containerName)
	}
	pvcRoot, err := validatePVCMountSource(hidden[0].Source, podUID, podsDir)
	if err != nil {
		return persistentSpecialConfig{}, false, err
	}
	lexicalLayerRoot := filepath.Join(pvcRoot, cleanPath)
	if err := rejectPersistentSpecialSymlinks(pvcRoot, lexicalLayerRoot); err != nil {
		return persistentSpecialConfig{}, false, err
	}
	layerRoot, err := securejoin.SecureJoin(pvcRoot, cleanPath)
	if err != nil {
		return persistentSpecialConfig{}, false, fmt.Errorf("resolve rootfs rw-layer path: %w", err)
	}

	dockerRoot, err := getInnerDockerDataRootPath(spec)
	if err != nil {
		return persistentSpecialConfig{}, false, err
	}
	k3sRoot, err := getInnerK3sDataDirPath(spec)
	if err != nil {
		return persistentSpecialConfig{}, false, err
	}
	for name, destination := range map[string]string{"Docker data-root": dockerRoot, "K3s data-dir": k3sRoot} {
		if !filepath.IsAbs(destination) || filepath.Clean(destination) == string(filepath.Separator) {
			return persistentSpecialConfig{}, false, fmt.Errorf("%s %q must be an absolute non-root path", name, destination)
		}
	}
	meta := persistentSpecialMeta{Version: persistentSpecialMetaVersion, Mappings: []persistentSpecialMapping{
		{Name: "docker", Destination: filepath.Clean(dockerRoot)},
		{Name: "k3s-agent", Destination: filepath.Join(filepath.Clean(k3sRoot), "agent")},
		{Name: "containerd-overlay", Destination: "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs"},
	}}
	return persistentSpecialConfig{
		entry:       entry,
		pvcRoot:     pvcRoot,
		layerRoot:   layerRoot,
		specialRoot: filepath.Join(layerRoot, "special"),
		meta:        meta,
	}, true, nil
}

func decodeRootfsRwLayerEntries(raw string) ([]rootfsRwLayerEntry, error) {
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	var entries []rootfsRwLayerEntry
	if err := decoder.Decode(&entries); err != nil {
		return nil, fmt.Errorf("decode %s: %w", rootfsRwLayerAnnotation, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("decode %s: trailing JSON data", rootfsRwLayerAnnotation)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("%s must contain at least one entry", rootfsRwLayerAnnotation)
	}
	return entries, nil
}

func cleanRelativeLayerPath(path string) (string, error) {
	if path == "" || path == "." {
		return "", nil
	}
	if filepath.IsAbs(path) {
		return "", fmt.Errorf("path must be relative")
	}
	cleaned := filepath.Clean(path)
	for _, elem := range strings.Split(cleaned, string(filepath.Separator)) {
		if elem == ".." {
			return "", fmt.Errorf("path must not escape the PVC root")
		}
	}
	return cleaned, nil
}

func validatePVCMountSource(source, podUID, podsDir string) (string, error) {
	cleanSource, err := filepath.Abs(source)
	if err != nil {
		return "", fmt.Errorf("resolve hidden PVC mount source: %w", err)
	}
	expectedPodRoot := filepath.Join(filepath.Clean(podsDir), podUID)
	volumeRoot := filepath.Join(expectedPodRoot, "volumes")
	rel, err := filepath.Rel(volumeRoot, cleanSource)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("hidden PVC mount source %q does not belong to Pod UID %q", source, podUID)
	}
	parts := strings.Split(rel, string(filepath.Separator))
	validVolumePath := len(parts) == 2 || len(parts) == 3 && parts[2] == "mount"
	if !validVolumePath || parts[0] == "" || parts[1] == "" {
		return "", fmt.Errorf("hidden PVC mount source %q is not a kubelet volume mount", source)
	}
	info, err := os.Lstat(cleanSource)
	if err != nil {
		return "", fmt.Errorf("stat hidden PVC mount source: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("hidden PVC mount source %q is not a real directory", source)
	}
	return cleanSource, nil
}

func rejectPersistentSpecialSymlinks(root, target string) error {
	root = filepath.Clean(root)
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("rootfs rw-layer path escapes PVC root")
	}
	current := root
	for _, elem := range append([]string{"."}, strings.Split(rel, string(filepath.Separator))...) {
		if elem != "." && elem != "" {
			current = filepath.Join(current, elem)
		}
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) {
			return nil
		}
		if statErr != nil {
			return fmt.Errorf("stat persistent special path: %w", statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("persistent special path %q contains a symlink", current)
		}
		if !info.IsDir() {
			return fmt.Errorf("persistent special path %q is not a directory", current)
		}
	}
	return nil
}

func initializePersistentSpecial(spec *specs.Spec, config persistentSpecialConfig, copyDir func(string, string) error) error {
	if err := os.MkdirAll(config.layerRoot, 0o755); err != nil {
		return fmt.Errorf("create persistent special layer root: %w", err)
	}
	lock, err := openPersistentSpecialLock(filepath.Join(config.layerRoot, ".special.lock"))
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("lock persistent special storage: %w", err)
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN) //nolint:errcheck

	if _, err := os.Lstat(config.specialRoot); err == nil {
		return validatePersistentSpecial(config)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat persistent special storage: %w", err)
	}

	staging, err := os.MkdirTemp(config.layerRoot, ".special.staging-")
	if err != nil {
		return fmt.Errorf("create persistent special staging directory: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(staging)
		}
	}()

	rootfs, err := filepath.Abs(spec.Root.Path)
	if err != nil {
		return fmt.Errorf("resolve container rootfs: %w", err)
	}
	for _, mapping := range config.meta.Mappings {
		destination := filepath.Join(staging, mapping.Name)
		if err := os.Mkdir(destination, 0o755); err != nil {
			return fmt.Errorf("create persistent special directory %s: %w", mapping.Name, err)
		}
		source, err := securejoin.SecureJoin(rootfs, mapping.Destination)
		if err != nil {
			return fmt.Errorf("resolve image special directory %s: %w", mapping.Destination, err)
		}
		info, err := os.Stat(source)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("stat image special directory %s: %w", mapping.Destination, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("image special path %s is not a directory", mapping.Destination)
		}
		if err := copyDir(source, destination); err != nil {
			return fmt.Errorf("initialize persistent special directory %s: %w", mapping.Name, err)
		}
	}
	metaData, err := json.MarshalIndent(config.meta, "", "  ")
	if err != nil {
		return fmt.Errorf("encode persistent special metadata: %w", err)
	}
	metaData = append(metaData, '\n')
	if err := os.WriteFile(filepath.Join(staging, "meta.json"), metaData, 0o644); err != nil {
		return fmt.Errorf("write persistent special metadata: %w", err)
	}
	if err := os.Rename(staging, config.specialRoot); err != nil {
		return fmt.Errorf("commit persistent special storage: %w", err)
	}
	committed = true
	return nil
}

func openPersistentSpecialLock(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open persistent special lock: %w", err)
	}
	return os.NewFile(uintptr(fd), path), nil
}

func validatePersistentSpecial(config persistentSpecialConfig) error {
	info, err := os.Lstat(config.specialRoot)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("persistent special storage is not a managed directory")
	}
	data, err := os.ReadFile(filepath.Join(config.specialRoot, "meta.json"))
	if err != nil {
		return fmt.Errorf("persistent special storage exists without valid metadata: %w", err)
	}
	var actual persistentSpecialMeta
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&actual); err != nil {
		return fmt.Errorf("decode persistent special metadata: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode persistent special metadata: trailing JSON data")
	}
	if !reflect.DeepEqual(actual, config.meta) {
		return fmt.Errorf("persistent special metadata does not match current directory mapping")
	}
	for _, mapping := range config.meta.Mappings {
		path := filepath.Join(config.specialRoot, mapping.Name)
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("persistent special directory %s is missing or invalid", mapping.Name)
		}
	}
	return nil
}

func rsyncPersistentSpecialDir(source, destination string) error {
	command := exec.Command("rsync", "-aHAX", "--numeric-ids", "--one-file-system", source+string(filepath.Separator), destination+string(filepath.Separator))
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("rsync failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}
