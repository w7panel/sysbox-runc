//go:build linux

package syscont

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/nestybox/sysbox-libs/idMap"
	sh "github.com/nestybox/sysbox-libs/idShiftUtils"
	"github.com/opencontainers/runc/libsysbox/sysbox"
	"github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

const volumeInitStateDir = "/run/sysbox/pvc-volume-init"

func initializePVCVolumes(sysbox *sysbox.Sysbox, spec *specs.Spec) error {
	return initializePVCVolumesAtWithState(spec, kubeletPodsDir, volumeInitStateDir, sysbox.BindMntUidShiftType, true)
}

func initializePVCVolumesAt(spec *specs.Spec, podsDir string, shiftType sh.IDShiftType, requireIDMap bool) error {
	return initializePVCVolumesAtWithState(spec, podsDir, filepath.Join(podsDir, ".sysbox-volume-init-state"), shiftType, requireIDMap)
}

func initializePVCVolumesAtWithState(spec *specs.Spec, podsDir, stateDir string, shiftType sh.IDShiftType, requireIDMap bool) error {
	if spec == nil || spec.Root == nil || spec.Root.Path == "" {
		return fmt.Errorf("container rootfs is missing")
	}
	containerName := spec.Annotations[kubernetesContainerNameAnno]
	// CRI forwards Pod annotations to the sandbox OCI spec too. The sandbox has
	// no Kubernetes container-name annotation and no application PVC mounts.
	if containerName == "" {
		return nil
	}
	podUID := spec.Annotations[kubernetesSandboxUIDAnno]
	if podUID == "" {
		// Direct runc use has no Kubernetes context. Do not infer host paths.
		return nil
	}
	rootfs, err := filepath.Abs(spec.Root.Path)
	if err != nil {
		return fmt.Errorf("resolve container rootfs: %w", err)
	}
	for _, mount := range spec.Mounts {
		if mount.Type != "bind" {
			continue
		}
		if hasMountOption(mount.Options, "ro") {
			continue
		}
		source, directory, ok, err := detectPVCSource(mount.Source, podUID, containerName, podsDir)
		if err != nil {
			return err
		}
		if !ok || !directory {
			continue
		}
		mount.Source = source
		stateKey := sha256.Sum256([]byte(source + "\x00" + mount.Destination))
		statePath := filepath.Join(stateDir, fmt.Sprintf("%x", stateKey))
		if err := seedEmptyPVCVolume(rootfs, mount, statePath, spec.Linux, shiftType, requireIDMap); err != nil {
			return err
		}
	}
	return nil
}

func hasMountOption(options []string, expected string) bool {
	for _, option := range options {
		if option == expected {
			return true
		}
	}
	return false
}

// detectPVCSource only accepts recognized kubelet PVC volume paths belonging to
// this Pod: generic CSI paths and K3s local-path's in-tree local-volume path.
// This deliberately avoids initializing emptyDir, projected volumes, hostPath,
// or an untrusted host bind mount without consulting the Kubernetes API.
func detectPVCSource(source, podUID, containerName, podsDir string) (string, bool, bool, error) {
	cleanSource, err := filepath.Abs(source)
	if err != nil {
		return "", false, false, fmt.Errorf("resolve PVC mount source: %w", err)
	}
	podRoot := filepath.Join(filepath.Clean(podsDir), podUID)
	directRoot := filepath.Join(podRoot, "volumes")
	if rel, relErr := filepath.Rel(directRoot, cleanSource); relErr == nil {
		parts := strings.Split(rel, string(filepath.Separator))
		if len(parts) == 3 && parts[0] == "kubernetes.io~csi" && parts[1] != "" && parts[2] == "mount" {
			source, directory, err := validatePVCSource(cleanSource)
			return source, directory, err == nil, err
		}
		// K3s local-path dynamically provisioned PVCs are surfaced via the
		// kubelet's in-tree local-volume layout rather than the generic CSI
		// layout. It is still per-Pod and kubelet-owned, so it has the same
		// trust boundary as the CSI source above.
		if len(parts) == 2 && parts[0] == "kubernetes.io~local-volume" && parts[1] != "" {
			source, directory, err := validatePVCSource(cleanSource)
			return source, directory, err == nil, err
		}
	}
	subpathRoot := filepath.Join(podRoot, "volume-subpaths")
	if rel, relErr := filepath.Rel(subpathRoot, cleanSource); relErr == nil {
		parts := strings.Split(rel, string(filepath.Separator))
		if len(parts) != 3 {
			return "", false, false, nil
		}
		// Kubelet may use the pod-spec container name for the volume-subpaths
		// directory while CRI gives the runtime the generated container name
		// (for example, "app" vs "app-54f8cb585c-gmz4v").
		containerDir := parts[1]
		containerMatches := containerDir == containerName || strings.HasPrefix(containerName, containerDir+"-")
		volumeDirMatches := strings.HasPrefix(parts[0], "pvc-") || isPVCVolumeName(podRoot, parts[0])
		if volumeDirMatches && containerDir != "" && containerMatches && parts[2] != "" {
			source, directory, err := validatePVCSource(cleanSource)
			return source, directory, err == nil, err
		}
	}
	return "", false, false, nil
}

func isPVCVolumeName(podRoot, volumeName string) bool {
	if volumeName == "" || strings.Contains(volumeName, string(filepath.Separator)) {
		return false
	}
	for _, source := range []string{
		filepath.Join(podRoot, "volumes", "kubernetes.io~csi", volumeName, "mount"),
		filepath.Join(podRoot, "volumes", "kubernetes.io~local-volume", volumeName),
	} {
		if _, err := os.Stat(source); err == nil {
			return true
		}
	}
	return false
}

func validatePVCSource(source string) (string, bool, error) {
	info, err := os.Lstat(source)
	if err != nil {
		return "", false, fmt.Errorf("stat PVC volume source: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", false, fmt.Errorf("PVC volume source %q is a symlink", source)
	}
	return source, info.IsDir(), nil
}

func validateVolumeInitIDMapMount(shiftType sh.IDShiftType, mount specs.Mount) error {
	if shiftType != sh.IDMappedMount && shiftType != sh.IDMappedMountOrShiftfs {
		return fmt.Errorf("PVC volume initialization for %s requires idmapped mounts", mount.Destination)
	}
	supported, err := idMap.IDMapMountSupportedOnPath(mount.Source)
	if err != nil {
		return fmt.Errorf("check idmapped mount support for PVC volume %s: %w", mount.Destination, err)
	}
	if !supported {
		return fmt.Errorf("PVC volume %s does not support idmapped mounts", mount.Destination)
	}
	return nil
}

func seedEmptyPVCVolume(rootfs string, mount specs.Mount, statePath string, linux *specs.Linux, shiftType sh.IDShiftType, requireIDMap bool) error {
	mountPath := mount.Destination
	destination := mount.Source
	fd, err := unix.Open(destination, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open PVC volume %s: %w", mountPath, err)
	}
	dir := os.NewFile(uintptr(fd), destination)
	defer dir.Close()
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		return fmt.Errorf("lock PVC volume %s: %w", mountPath, err)
	}
	defer unix.Flock(fd, unix.LOCK_UN) //nolint:errcheck

	empty, err := pvcVolumeEmpty(destination)
	if err != nil {
		return fmt.Errorf("inspect PVC volume %s: %w", mountPath, err)
	}
	retry, err := pvcVolumeRetryPending(statePath)
	if err != nil {
		return fmt.Errorf("inspect PVC volume initialization state for %s: %w", mountPath, err)
	}
	if !empty && !retry {
		return nil
	}
	relative := strings.TrimPrefix(filepath.Clean(mountPath), string(filepath.Separator))
	if relative == "." {
		relative = ""
	}
	imagePath := filepath.Join(rootfs, relative)
	validationPath := imagePath
	if relative != "" {
		validationPath = filepath.Dir(imagePath)
	}
	if err := rejectPersistentSpecialSymlinks(rootfs, validationPath); err != nil {
		return fmt.Errorf("validate image volume path %s: %w", mountPath, err)
	}
	info, err := os.Lstat(imagePath)
	if errors.Is(err, os.ErrNotExist) {
		if retry {
			if removeErr := os.Remove(statePath); removeErr != nil {
				return fmt.Errorf("complete empty PVC volume initialization for %s: %w", mountPath, removeErr)
			}
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat image volume path %s: %w", mountPath, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("image volume path %s is a symlink", mountPath)
	}
	if !info.IsDir() {
		if retry {
			if removeErr := os.Remove(statePath); removeErr != nil {
				return fmt.Errorf("complete empty PVC volume initialization for %s: %w", mountPath, removeErr)
			}
		}
		return nil
	}
	if err := rejectPersistentSpecialSymlinks(rootfs, imagePath); err != nil {
		return fmt.Errorf("validate image volume path %s: %w", mountPath, err)
	}
	imageSource, err := securejoin.SecureJoin(rootfs, relative)
	if err != nil {
		return fmt.Errorf("resolve image volume path %s: %w", mountPath, err)
	}
	if requireIDMap {
		if err := validateVolumeInitIDMapMount(shiftType, mount); err != nil {
			return err
		}
	}
	if err := ensureVolumeInitStateDir(filepath.Dir(statePath)); err != nil {
		return fmt.Errorf("create PVC volume initialization state directory: %w", err)
	}
	stateFD, err := unix.Open(statePath, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("create PVC volume initialization state for %s: %w", mountPath, err)
	}
	_ = unix.Close(stateFD)
	var uidMappings, gidMappings []specs.LinuxIDMapping
	if linux != nil {
		uidMappings = linux.UIDMappings
		gidMappings = linux.GIDMappings
	}
	if err := rsyncPVCVolumeDir(imageSource, destination, uidMappings, gidMappings); err != nil {
		return fmt.Errorf("initialize PVC volume %s: %w", mountPath, err)
	}
	if err := os.Remove(statePath); err != nil {
		return fmt.Errorf("complete PVC volume initialization for %s: %w", mountPath, err)
	}
	return nil
}

func pvcVolumeEmpty(root string) (bool, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if entry.Name() != "lost+found" {
			return false, nil
		}
	}
	return true, nil
}

func pvcVolumeRetryPending(statePath string) (bool, error) {
	info, err := os.Lstat(statePath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return false, fmt.Errorf("unsafe initialization state file")
	}
	var stat unix.Stat_t
	if err := unix.Lstat(statePath, &stat); err != nil {
		return false, err
	}
	if stat.Uid != 0 {
		return false, fmt.Errorf("initialization state file is not owned by root")
	}
	return true, nil
}

func ensureVolumeInitStateDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("unsafe state directory permissions")
	}
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		return err
	}
	if stat.Uid != 0 {
		return fmt.Errorf("state directory is not owned by root")
	}
	return nil
}

func rsyncPVCVolumeDir(source, destination string, uidMappings, gidMappings []specs.LinuxIDMapping) error {
	uidMap, gidMap, err := persistentSpecialRsyncIDMaps(source, uidMappings, gidMappings)
	if err != nil {
		return err
	}
	args := []string{"-aHAX", "--numeric-ids", "--one-file-system", "--exclude=/lost+found"}
	if uidMap != "" {
		args = append(args, "--usermap="+uidMap)
	}
	if gidMap != "" {
		args = append(args, "--groupmap="+gidMap)
	}
	args = append(args, source+string(filepath.Separator), destination+string(filepath.Separator))
	output, err := exec.Command("rsync", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("rsync failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}
