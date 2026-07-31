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
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
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

	if err := initializePersistentUpperMounts(spec, config); err != nil {
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

// initializePersistentUpperMounts creates the raw-upper mount sources. On their
// first creation, it seeds each source from the merged image rootfs before runc
// installs the bind mount that would otherwise hide the image contents. Existing
// directories are PVC state and are never re-seeded or overwritten.
func initializePersistentUpperMounts(spec *specs.Spec, config persistentSpecialConfig) error {
	if spec == nil || spec.Root == nil || spec.Root.Path == "" {
		return fmt.Errorf("container rootfs is missing")
	}
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

	rootfs, err := filepath.Abs(spec.Root.Path)
	if err != nil {
		return fmt.Errorf("resolve container rootfs: %w", err)
	}
	for _, mapping := range config.mappings {
		destination, err := persistentUpperMountSource(config, mapping)
		if err != nil {
			return err
		}
		info, statErr := os.Lstat(destination)
		if statErr == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return fmt.Errorf("persistent upper directory %s is missing or invalid", mapping.Destination)
			}
			continue
		}
		if !errors.Is(statErr, os.ErrNotExist) {
			return fmt.Errorf("stat persistent upper directory %s: %w", mapping.Destination, statErr)
		}

		var uidMappings, gidMappings []specs.LinuxIDMapping
		if spec.Linux != nil {
			uidMappings = spec.Linux.UIDMappings
			gidMappings = spec.Linux.GIDMappings
		}
		if err := seedPersistentUpperDirectory(rootfs, destination, mapping, uidMappings, gidMappings); err != nil {
			return err
		}
	}
	return validatePersistentUpperMounts(config)
}

// seedPersistentUpperDirectory publishes one initialized directory atomically.
// Its destination is intentionally not created before the seed completes: the
// existence of that directory is the durable indication that PVC state owns it.
func seedPersistentUpperDirectory(rootfs, destination string, mapping persistentSpecialMapping, uidMappings, gidMappings []specs.LinuxIDMapping) error {
	parent := filepath.Dir(destination)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("create persistent upper parent for %s: %w", mapping.Destination, err)
	}
	staging, err := os.MkdirTemp(parent, "."+filepath.Base(destination)+".seed-")
	if err != nil {
		return fmt.Errorf("create persistent upper staging directory %s: %w", mapping.Destination, err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(staging)
		}
	}()

	relative := strings.TrimPrefix(filepath.Clean(mapping.Destination), string(filepath.Separator))
	lexicalSource := filepath.Join(rootfs, relative)
	if err := rejectPersistentSpecialSymlinks(rootfs, lexicalSource); err != nil {
		return fmt.Errorf("validate image special directory %s: %w", mapping.Destination, err)
	}
	source, err := securejoin.SecureJoin(rootfs, relative)
	if err != nil {
		return fmt.Errorf("resolve image special directory %s: %w", mapping.Destination, err)
	}
	info, err := os.Lstat(source)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("image special path %s is not a real directory", mapping.Destination)
		}
		if err := rsyncPersistentSpecialDir(source, staging, uidMappings, gidMappings); err != nil {
			return fmt.Errorf("seed persistent upper directory %s: %w", mapping.Destination, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat image special directory %s: %w", mapping.Destination, err)
	}

	if err := os.Rename(staging, destination); err != nil {
		return fmt.Errorf("commit persistent upper directory %s: %w", mapping.Destination, err)
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

func rsyncPersistentSpecialDir(source, destination string, uidMappings, gidMappings []specs.LinuxIDMapping) error {
	uidMap, gidMap, err := persistentSpecialRsyncIDMaps(source, uidMappings, gidMappings)
	if err != nil {
		return err
	}
	args := []string{"-aHAX", "--numeric-ids", "--one-file-system"}
	if uidMap != "" {
		args = append(args, "--usermap="+uidMap)
	}
	if gidMap != "" {
		args = append(args, "--groupmap="+gidMap)
	}
	args = append(args, source+string(filepath.Separator), destination+string(filepath.Separator))
	command := exec.Command("rsync", args...)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("rsync failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func persistentSpecialRsyncIDMaps(root string, uidMappings, gidMappings []specs.LinuxIDMapping) (string, string, error) {
	uids := map[uint32]struct{}{}
	gids := map[uint32]struct{}{}
	err := filepath.WalkDir(root, func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		var stat unix.Stat_t
		if err := unix.Lstat(path, &stat); err != nil {
			return err
		}
		uids[stat.Uid] = struct{}{}
		gids[stat.Gid] = struct{}{}
		return nil
	})
	if err != nil {
		return "", "", fmt.Errorf("scan persistent special source: %w", err)
	}
	uidMap, err := persistentSpecialRsyncIDMap(uids, uidMappings)
	if err != nil {
		return "", "", fmt.Errorf("map persistent special uids: %w", err)
	}
	gidMap, err := persistentSpecialRsyncIDMap(gids, gidMappings)
	if err != nil {
		return "", "", fmt.Errorf("map persistent special gids: %w", err)
	}
	return uidMap, gidMap, nil
}

func persistentSpecialRsyncIDMap(ids map[uint32]struct{}, mappings []specs.LinuxIDMapping) (string, error) {
	type idPair struct {
		from uint32
		to   uint32
	}
	pairs := make([]idPair, 0, len(ids))
	for id := range ids {
		mapped, found, err := persistentSpecialContainerID(id, mappings)
		if err != nil {
			return "", err
		}
		if found && mapped != id {
			pairs = append(pairs, idPair{from: id, to: mapped})
		}
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].from < pairs[j].from })
	result := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		result = append(result, strconv.FormatUint(uint64(pair.from), 10)+":"+strconv.FormatUint(uint64(pair.to), 10))
	}
	return strings.Join(result, ","), nil
}

func persistentSpecialContainerID(id uint32, mappings []specs.LinuxIDMapping) (uint32, bool, error) {
	for _, mapping := range mappings {
		if mapping.Size == 0 {
			return 0, false, fmt.Errorf("ID mapping size is zero")
		}
		hostEnd := uint64(mapping.HostID) + uint64(mapping.Size)
		containerEnd := uint64(mapping.ContainerID) + uint64(mapping.Size)
		if hostEnd > uint64(^uint32(0))+1 || containerEnd > uint64(^uint32(0))+1 {
			return 0, false, fmt.Errorf("ID mapping overflows uint32")
		}
		if uint64(id) >= uint64(mapping.HostID) && uint64(id) < hostEnd {
			return mapping.ContainerID + (id - mapping.HostID), true, nil
		}
	}
	return id, false, nil
}
