//go:build linux
// +build linux

package syscont

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

const (
	rootfsRwLayerAnnotation     = "sysbox/rootfs-rw-layer"
	persistentSpecialAnnotation = "sysbox/persistent-special-mounts"
	kubernetesContainerNameAnno = "io.kubernetes.cri.container-name"
	kubernetesSandboxUIDAnno    = "io.kubernetes.cri.sandbox-uid"
	rootfsSpecialMountBase      = "/var/lib/sysbox/rootfs-special-volume"
	persistentSpecialHandoffDir = "/run/sysbox/rootfs-pvc-handoff"
	persistentSpecialHandoffVer = 1
	kubeletPodsDir              = "/var/lib/kubelet/pods"
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

type persistentSpecialConfig struct {
	entry     rootfsRwLayerEntry
	pvcRoot   string
	layerRoot string
	upperRoot string
	mappings  []persistentSpecialMapping
}

type persistentSpecialHandoff struct {
	Version       int    `json:"version"`
	SnapshotKey   string `json:"snapshotKey"`
	PodUID        string `json:"podUID"`
	ContainerName string `json:"containerName"`
	VolumeName    string `json:"volumeName"`
	PVCMountPath  string `json:"pvcMountPath"`
}

// cfgPersistentSpecialMounts converts a snapshotter handoff (or a legacy
// admission-injected PVC mount) into explicit persistent special mounts.
func cfgPersistentSpecialMounts(spec *specs.Spec, containerID string) error {
	return cfgPersistentSpecialMountsWithHandoffAt(spec, kubeletPodsDir, persistentSpecialHandoffDir, containerID)
}

func cfgPersistentSpecialMountsAt(spec *specs.Spec, podsDir string) error {
	return cfgPersistentSpecialMountsWithHandoffAt(spec, podsDir, "", "")
}

func cfgPersistentSpecialMountsWithHandoffAt(spec *specs.Spec, podsDir, handoffDir, containerID string) error {
	config, enabled, err := resolvePersistentSpecialConfigWithHandoff(spec, podsDir, handoffDir, containerID)
	if err != nil || !enabled {
		return err
	}

	if err := initializePersistentUpperMounts(config); err != nil {
		return err
	}

	hiddenDest := filepath.Join(rootfsSpecialMountBase, config.entry.VolumeName)
	persistentDestinations := make(map[string]struct{}, len(config.mappings))
	for _, mapping := range config.mappings {
		persistentDestinations[filepath.Clean(mapping.Destination)] = struct{}{}
	}
	filtered := make([]specs.Mount, 0, len(spec.Mounts)+len(config.mappings))
	for _, mount := range spec.Mounts {
		destination := filepath.Clean(mount.Destination)
		if destination == hiddenDest {
			continue
		}
		if _, replaced := persistentDestinations[destination]; replaced {
			continue
		}
		filtered = append(filtered, mount)
	}
	for _, mapping := range config.mappings {
		source, err := persistentUpperMountSource(config, mapping)
		if err != nil {
			return err
		}
		filtered = append(filtered, specs.Mount{
			Source:      source,
			Destination: mapping.Destination,
			Type:        "bind",
			Options:     []string{"rbind", "rprivate"},
		})
	}
	spec.Mounts = filtered
	return nil
}

func resolvePersistentSpecialConfig(spec *specs.Spec, podsDir string) (persistentSpecialConfig, bool, error) {
	return resolvePersistentSpecialConfigWithHandoff(spec, podsDir, "", "")
}

func resolvePersistentSpecialConfigWithHandoff(spec *specs.Spec, podsDir, handoffDir, containerID string) (persistentSpecialConfig, bool, error) {
	if spec.Annotations[persistentSpecialAnnotation] != "true" {
		return persistentSpecialConfig{}, false, nil
	}
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
	if reservedMountCount > 0 && len(hidden) != 1 {
		return persistentSpecialConfig{}, false, fmt.Errorf("container %q requires exactly one hidden PVC mount at %s; found %d", containerName, hiddenDest, len(hidden))
	}
	if len(hidden) == 1 && (hidden[0].Type != "bind" || !filepath.IsAbs(hidden[0].Source)) {
		return persistentSpecialConfig{}, false, fmt.Errorf("hidden PVC mount at %s is not an absolute bind mount", hiddenDest)
	}
	podUID := spec.Annotations[kubernetesSandboxUIDAnno]
	if podUID == "" {
		return persistentSpecialConfig{}, false, fmt.Errorf("container %q Kubernetes sandbox UID annotation is missing", containerName)
	}
	if filepath.Base(podUID) != podUID || podUID == "." || podUID == ".." {
		return persistentSpecialConfig{}, false, fmt.Errorf("container %q Kubernetes sandbox UID annotation is unsafe", containerName)
	}
	var pvcRoot string
	if len(hidden) == 1 {
		pvcRoot, err = validatePVCMountSource(hidden[0].Source, podUID, podsDir)
		if err != nil {
			return persistentSpecialConfig{}, false, err
		}
	}
	handoff, found, err := loadPersistentSpecialHandoff(handoffDir, containerID)
	if err != nil {
		return persistentSpecialConfig{}, false, err
	}
	if found {
		if handoff.Version != persistentSpecialHandoffVer || handoff.SnapshotKey != containerID || handoff.PodUID != podUID || handoff.ContainerName != containerName || handoff.VolumeName != entry.VolumeName {
			return persistentSpecialConfig{}, false, fmt.Errorf("persistent special handoff does not match the current container")
		}
		handoffRoot, err := validatePVCMountSource(handoff.PVCMountPath, podUID, podsDir)
		if err != nil {
			return persistentSpecialConfig{}, false, err
		}
		if pvcRoot != "" && pvcRoot != handoffRoot {
			return persistentSpecialConfig{}, false, fmt.Errorf("persistent special handoff and hidden PVC mount disagree")
		}
		pvcRoot = handoffRoot
	}
	if pvcRoot == "" {
		return persistentSpecialConfig{}, false, fmt.Errorf("container %q persistent special PVC source is unavailable", containerName)
	}
	lexicalLayerRoot := filepath.Join(pvcRoot, cleanPath)
	if err := rejectPersistentSpecialSymlinks(pvcRoot, lexicalLayerRoot); err != nil {
		return persistentSpecialConfig{}, false, err
	}
	layerRoot, err := securejoin.SecureJoin(pvcRoot, cleanPath)
	if err != nil {
		return persistentSpecialConfig{}, false, fmt.Errorf("resolve rootfs rw-layer path: %w", err)
	}

	infos, err := getSpecialDirInfos(spec)
	if err != nil {
		return persistentSpecialConfig{}, false, err
	}
	mappings := make([]persistentSpecialMapping, 0, len(infos))
	for _, info := range infos {
		destination := filepath.Clean(info.destination)
		if !filepath.IsAbs(destination) || destination == string(filepath.Separator) {
			return persistentSpecialConfig{}, false, fmt.Errorf("special directory %s destination %q must be an absolute non-root path", info.name, info.destination)
		}
		mappings = append(mappings, persistentSpecialMapping{Name: info.name, Destination: destination})
	}
	for i := range mappings {
		for j := i + 1; j < len(mappings); j++ {
			left := mappings[i].Destination
			right := mappings[j].Destination
			if left == right || strings.HasPrefix(left, right+string(filepath.Separator)) || strings.HasPrefix(right, left+string(filepath.Separator)) {
				return persistentSpecialConfig{}, false, fmt.Errorf("special directory destinations %q and %q overlap", left, right)
			}
		}
	}
	return persistentSpecialConfig{
		entry:     entry,
		pvcRoot:   pvcRoot,
		layerRoot: layerRoot,
		upperRoot: filepath.Join(layerRoot, "upper"),
		mappings:  mappings,
	}, true, nil
}

func loadPersistentSpecialHandoff(root, containerID string) (persistentSpecialHandoff, bool, error) {
	if root == "" || containerID == "" {
		return persistentSpecialHandoff{}, false, nil
	}
	sum := sha256.Sum256([]byte(containerID))
	path := filepath.Join(root, hex.EncodeToString(sum[:])+".json")
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return persistentSpecialHandoff{}, false, nil
	}
	if err != nil {
		return persistentSpecialHandoff{}, false, fmt.Errorf("open persistent special handoff: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return persistentSpecialHandoff{}, false, fmt.Errorf("stat persistent special handoff: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return persistentSpecialHandoff{}, false, fmt.Errorf("persistent special handoff has unsafe permissions")
	}
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var handoff persistentSpecialHandoff
	if err := decoder.Decode(&handoff); err != nil {
		return persistentSpecialHandoff{}, false, fmt.Errorf("decode persistent special handoff: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return persistentSpecialHandoff{}, false, fmt.Errorf("decode persistent special handoff: trailing JSON data")
	}
	return handoff, true, nil
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

func initializePersistentUpperMounts(config persistentSpecialConfig) error {
	if err := os.MkdirAll(config.layerRoot, 0o755); err != nil {
		return fmt.Errorf("create persistent upper layer root: %w", err)
	}
	if err := rejectPersistentSpecialSymlinks(config.layerRoot, config.upperRoot); err != nil {
		return err
	}
	if err := os.MkdirAll(config.upperRoot, 0o755); err != nil {
		return fmt.Errorf("create persistent upper root: %w", err)
	}
	lock, err := openPersistentSpecialLock(filepath.Join(config.layerRoot, ".persistent-upper-mounts.lock"))
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("lock persistent upper mounts: %w", err)
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN) //nolint:errcheck

	for _, mapping := range config.mappings {
		source, err := persistentUpperMountSource(config, mapping)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(source, 0o755); err != nil {
			return fmt.Errorf("create persistent upper directory %s: %w", mapping.Destination, err)
		}
	}
	return validatePersistentUpperMounts(config)
}

func openPersistentSpecialLock(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open persistent special lock: %w", err)
	}
	return os.NewFile(uintptr(fd), path), nil
}

func persistentUpperMountSource(config persistentSpecialConfig, mapping persistentSpecialMapping) (string, error) {
	relative := strings.TrimPrefix(filepath.Clean(mapping.Destination), string(filepath.Separator))
	lexical := filepath.Join(config.upperRoot, relative)
	if err := rejectPersistentSpecialSymlinks(config.upperRoot, lexical); err != nil {
		return "", err
	}
	source, err := securejoin.SecureJoin(config.upperRoot, relative)
	if err != nil {
		return "", fmt.Errorf("resolve persistent upper directory %s: %w", mapping.Destination, err)
	}
	return source, nil
}

func validatePersistentUpperMounts(config persistentSpecialConfig) error {
	info, err := os.Lstat(config.upperRoot)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("persistent upper root is missing or invalid")
	}
	for _, mapping := range config.mappings {
		source, err := persistentUpperMountSource(config, mapping)
		if err != nil {
			return err
		}
		entryInfo, err := os.Lstat(source)
		if err != nil || entryInfo.Mode()&os.ModeSymlink != 0 || !entryInfo.IsDir() {
			return fmt.Errorf("persistent upper directory %s is missing or invalid", mapping.Destination)
		}
	}
	return nil
}
