//go:build linux
// +build linux

package syscont

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

func writePersistentSpecialHandoff(t *testing.T, root, containerID string, handoff persistentSpecialHandoff) {
	t.Helper()
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(handoff)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(containerID))
	path := filepath.Join(root, hex.EncodeToString(sum[:])+".json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRsyncMetadataUnsupported(t *testing.T) {
	tests := []struct {
		name string
		text string
		want bool
	}{
		{name: "acl client", text: "rsync: ACLs are not supported on this client", want: true},
		{name: "xattr client", text: "xattrs are not supported", want: true},
		{name: "ordinary io", text: "rsync: connection unexpectedly closed", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rsyncMetadataUnsupported(tt.text); got != tt.want {
				t.Fatalf("rsyncMetadataUnsupported(%q) = %v, want %v", tt.text, got, tt.want)
			}
		})
	}
}

func persistentSpecialTestSpec(t *testing.T, podsDir, podUID, layerPath string) (*specs.Spec, string) {
	t.Helper()
	pvcRoot := filepath.Join(podsDir, podUID, "volumes", "kubernetes.io~csi", "pvc-test", "mount")
	if err := os.MkdirAll(pvcRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	rootfs := t.TempDir()
	for _, path := range []string{
		"var/lib/docker",
		"var/lib/kubelet",
		"var/lib/k0s",
		"var/lib/rancher/k3s",
		"var/lib/rancher/rke2",
		"var/lib/buildkit",
		"var/lib/containerd/io.containerd.snapshotter.v1.overlayfs",
	} {
		if err := os.MkdirAll(filepath.Join(rootfs, path), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	raw := `[{"name":"app","volumeName":"rootfs","path":"` + layerPath + `","persistentSpecialMounts":true}]`
	return &specs.Spec{
		Root: &specs.Root{Path: rootfs},
		Linux: &specs.Linux{
			UIDMappings: []specs.LinuxIDMapping{{ContainerID: 0, HostID: 100000, Size: 65536}},
			GIDMappings: []specs.LinuxIDMapping{{ContainerID: 0, HostID: 200000, Size: 65536}},
		},
		Annotations: map[string]string{
			rootfsRwLayerAnnotation:     raw,
			kubernetesContainerNameAnno: "app",
			kubernetesSandboxUIDAnno:    podUID,
		},
		Mounts: []specs.Mount{{
			Source:      pvcRoot,
			Destination: filepath.Join(rootfsSpecialMountBase, "rootfs"),
			Type:        "bind",
		}},
	}, pvcRoot
}

func TestCfgPersistentSpecialMountsRequiresExplicitOptIn(t *testing.T) {
	podsDir := t.TempDir()
	spec, _ := persistentSpecialTestSpec(t, podsDir, "pod-uid", "containers/app")
	spec.Annotations[rootfsRwLayerAnnotation] = `[{"name":"app","volumeName":"rootfs","path":"containers/app"}]`
	original := append([]specs.Mount(nil), spec.Mounts...)

	if err := cfgPersistentSpecialMountsAt(spec, podsDir); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(spec.Mounts, original) {
		t.Fatalf("mounts changed without explicit opt-in: %#v", spec.Mounts)
	}

	spec.Annotations[rootfsRwLayerAnnotation] = `[{"name":"app","volumeName":"rootfs","path":"containers/app","persistentSpecialMounts":false}]`
	if err := cfgPersistentSpecialMountsAt(spec, podsDir); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(spec.Mounts, original) {
		t.Fatalf("mounts changed with opt-in disabled: %#v", spec.Mounts)
	}
}

func TestCfgPersistentSpecialMountsUsesCustomSpecialPath(t *testing.T) {
	podsDir := t.TempDir()
	spec, pvcRoot := persistentSpecialTestSpec(t, podsDir, "pod-uid", "containers/app")
	spec.Annotations[rootfsRwLayerAnnotation] = `[{"name":"app","volumeName":"rootfs","path":"containers/app","persistentSpecialMounts":true,"specialPath":["/srv/custom"]}]`
	if err := os.MkdirAll(filepath.Join(spec.Root.Path, "srv/custom"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(spec.Root.Path, "srv/custom/from-image"), []byte("seed"), 0o640); err != nil {
		t.Fatal(err)
	}

	if err := cfgPersistentSpecialMountsAt(spec, podsDir); err != nil {
		t.Fatal(err)
	}
	var custom *specs.Mount
	for i := range spec.Mounts {
		if spec.Mounts[i].Destination == "/srv/custom" {
			custom = &spec.Mounts[i]
			break
		}
	}
	if custom == nil {
		t.Fatal("custom special mount was not generated")
	}
	wantSource := filepath.Join(pvcRoot, "containers/app/special/srv/custom")
	if custom.Source != wantSource {
		t.Fatalf("custom source = %q, want %q", custom.Source, wantSource)
	}
	if data, err := os.ReadFile(filepath.Join(wantSource, "from-image")); err != nil || string(data) != "seed" {
		t.Fatalf("custom image seed = %q, err=%v", data, err)
	}
}

func TestCfgPersistentSpecialMountsRejectsCustomPathWithoutOptIn(t *testing.T) {
	podsDir := t.TempDir()
	spec, _ := persistentSpecialTestSpec(t, podsDir, "pod-uid", "containers/app")
	spec.Annotations[rootfsRwLayerAnnotation] = `[{"name":"app","volumeName":"rootfs","path":"containers/app","specialPath":["/srv/custom"]}]`

	err := cfgPersistentSpecialMountsAt(spec, podsDir)
	if err == nil || !strings.Contains(err.Error(), "specialPath requires persistentSpecialMounts") {
		t.Fatalf("error = %v", err)
	}
}

func TestCfgPersistentSpecialMountsDoesNothingWithoutMatchingEntry(t *testing.T) {
	spec := &specs.Spec{Annotations: map[string]string{}}
	original := append([]specs.Mount(nil), spec.Mounts...)
	if err := cfgPersistentSpecialMountsAt(spec, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(spec.Mounts, original) {
		t.Fatalf("mounts changed without annotation: %#v", spec.Mounts)
	}

	spec.Annotations = map[string]string{
		rootfsRwLayerAnnotation:     `[{"name":"other","volumeName":"rootfs","path":"other","persistentSpecialMounts":true}]`,
		kubernetesContainerNameAnno: "app",
	}
	if err := cfgPersistentSpecialMountsAt(spec, t.TempDir()); err != nil {
		t.Fatal(err)
	}
}

func TestCfgPersistentSpecialMountsSkipsPodSandbox(t *testing.T) {
	spec := &specs.Spec{Annotations: map[string]string{
		rootfsRwLayerAnnotation: `[{"name":"app","volumeName":"rootfs","path":"app","persistentSpecialMounts":true}]`,
	}}
	if err := cfgPersistentSpecialMountsAt(spec, t.TempDir()); err != nil {
		t.Fatalf("sandbox spec must be ignored: %v", err)
	}
	spec.Mounts = []specs.Mount{{Destination: filepath.Join(rootfsSpecialMountBase, "rootfs")}}
	if err := cfgPersistentSpecialMountsAt(spec, t.TempDir()); err == nil || !strings.Contains(err.Error(), "container name annotation is missing") {
		t.Fatalf("reserved sandbox mount error = %v", err)
	}
}

func TestCfgPersistentSpecialMountsInitializesAndReusesPVCStorage(t *testing.T) {
	podsDir := t.TempDir()
	spec, pvcRoot := persistentSpecialTestSpec(t, podsDir, "pod-uid", "containers/app")
	spec.Mounts = append(spec.Mounts, specs.Mount{
		Source:      "/node-local-kubelet",
		Destination: "/var/lib/kubelet",
		Type:        "bind",
	})
	if err := os.WriteFile(filepath.Join(spec.Root.Path, "var/lib/docker/from-image"), []byte("preloaded"), 0o644); err != nil {
		t.Fatal(err)
	}
	config, enabled, err := resolvePersistentSpecialConfig(spec, podsDir)
	if err != nil || !enabled {
		t.Fatalf("resolve config: enabled=%v err=%v", enabled, err)
	}
	if err := initializePersistentSpecialMounts(spec, config); err != nil {
		t.Fatal(err)
	}
	for _, mapping := range config.mappings {
		source, err := persistentSpecialMountSource(config, mapping)
		if err != nil {
			t.Fatal(err)
		}
		if info, err := os.Stat(source); err != nil || !info.IsDir() {
			t.Fatalf("mapping %s not initialized: %v", mapping.Name, err)
		}
	}
	dockerSource := filepath.Join(config.specialRoot, "var/lib/docker")
	if data, err := os.ReadFile(filepath.Join(dockerSource, "from-image")); err != nil || string(data) != "preloaded" {
		t.Fatalf("image preload = %q err=%v", data, err)
	}
	if err := os.WriteFile(filepath.Join(dockerSource, "persistent"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	var ownershipBefore unix.Stat_t
	if err := unix.Lstat(filepath.Join(dockerSource, "persistent"), &ownershipBefore); err != nil {
		t.Fatal(err)
	}
	if err := unix.Setxattr(filepath.Join(dockerSource, "persistent"), "user.sysbox-test", []byte("kept"), 0); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(spec.Root.Path, "var/lib/docker/after-first"), []byte("new-image-data"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Simulate another Pod reusing the PVC with a different user namespace.
	// Existing PVC state must not be re-seeded or ownership-shifted.
	spec.Linux.UIDMappings = []specs.LinuxIDMapping{{ContainerID: 0, HostID: 300000, Size: 65536}}
	spec.Linux.GIDMappings = []specs.LinuxIDMapping{{ContainerID: 0, HostID: 400000, Size: 65536}}
	if err := initializePersistentSpecialMounts(spec, config); err != nil {
		t.Fatalf("reuse failed: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(dockerSource, "persistent")); err != nil || string(data) != "data" {
		t.Fatalf("persistent data = %q err=%v", data, err)
	}
	var persistentStat unix.Stat_t
	if err := unix.Lstat(filepath.Join(dockerSource, "persistent"), &persistentStat); err != nil {
		t.Fatal(err)
	}
	if persistentStat.Uid != ownershipBefore.Uid || persistentStat.Gid != ownershipBefore.Gid {
		t.Fatalf("persistent ownership changed from %d:%d to %d:%d", ownershipBefore.Uid, ownershipBefore.Gid, persistentStat.Uid, persistentStat.Gid)
	}
	xattr := make([]byte, 16)
	size, err := unix.Getxattr(filepath.Join(dockerSource, "persistent"), "user.sysbox-test", xattr)
	if err != nil {
		t.Fatal(err)
	}
	if string(xattr[:size]) != "kept" {
		t.Fatalf("persistent xattr = %q", xattr[:size])
	}
	if _, err := os.Stat(filepath.Join(dockerSource, "after-first")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("existing PVC directory was re-seeded: %v", err)
	}
	if info, err := os.Stat(filepath.Join(config.layerRoot, "special")); err != nil || !info.IsDir() {
		t.Fatalf("special directory err = %v, want directory", err)
	}
	if _, err := os.Stat(filepath.Join(config.layerRoot, "upper", ".sysbox-special")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy special directory err = %v, want not exist", err)
	}

	if err := cfgPersistentSpecialMountsAt(spec, podsDir); err != nil {
		t.Fatal(err)
	}
	if len(spec.Mounts) != 7 {
		t.Fatalf("got %d mounts, want 7: %#v", len(spec.Mounts), spec.Mounts)
	}
	for index, mapping := range config.mappings {
		mount := spec.Mounts[index]
		wantSource := filepath.Join(pvcRoot, "containers/app/special", strings.TrimPrefix(mapping.Destination, "/"))
		if mount.Source != wantSource ||
			mount.Destination != mapping.Destination || mount.Type != "bind" ||
			!reflect.DeepEqual(mount.Options, []string{"rbind", "rprivate"}) {
			t.Fatalf("unexpected persistent mount: %#v", mount)
		}
	}
	for _, mount := range spec.Mounts {
		if mount.Source == "/node-local-kubelet" {
			t.Fatalf("node-local special mount was not replaced: %#v", mount)
		}
	}
}

func TestPersistentSpecialRsyncIDMapStoresCanonicalContainerIDs(t *testing.T) {
	ids := map[uint32]struct{}{0: {}, 100000: {}, 100123: {}}
	mappings := []specs.LinuxIDMapping{{ContainerID: 0, HostID: 100000, Size: 65536}}

	got, err := persistentSpecialRsyncIDMap(ids, mappings)
	if err != nil {
		t.Fatal(err)
	}
	if got != "100000:0,100123:123" {
		t.Fatalf("ID map = %q, want canonical container IDs", got)
	}
}

func TestInitializePersistentSpecialMountsCreatesEmptyDirectoryForMissingImagePath(t *testing.T) {
	rootfs := t.TempDir()
	specialRoot := filepath.Join(t.TempDir(), "special")
	spec := &specs.Spec{Root: &specs.Root{Path: rootfs}}
	config := persistentSpecialConfig{
		layerRoot:   filepath.Dir(specialRoot),
		specialRoot: specialRoot,
		mappings:    []persistentSpecialMapping{{Name: "missing", Destination: "/var/lib/missing"}},
	}
	if err := initializePersistentSpecialMounts(spec, config); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(specialRoot, "var/lib/missing")
	entries, err := os.ReadDir(destination)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("missing image path initialized with entries: %#v", entries)
	}
}

func TestInitializePersistentSpecialMountsRejectsInvalidImageSource(t *testing.T) {
	tests := []struct {
		name   string
		create func(t *testing.T, path string)
	}{
		{
			name: "regular file",
			create: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, []byte("not a directory"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "symlink",
			create: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Symlink(t.TempDir(), path); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rootfs := t.TempDir()
			source := filepath.Join(rootfs, "var/lib/docker")
			if err := os.MkdirAll(filepath.Dir(source), 0o755); err != nil {
				t.Fatal(err)
			}
			test.create(t, source)
			specialRoot := filepath.Join(t.TempDir(), "special")
			spec := &specs.Spec{Root: &specs.Root{Path: rootfs}}
			config := persistentSpecialConfig{
				layerRoot:   filepath.Dir(specialRoot),
				specialRoot: specialRoot,
				mappings:    []persistentSpecialMapping{{Name: "docker", Destination: "/var/lib/docker"}},
			}
			if err := initializePersistentSpecialMounts(spec, config); err == nil {
				t.Fatal("expected invalid image source error")
			}
			if _, err := os.Stat(filepath.Join(specialRoot, "var/lib/docker")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid image source published a target: %v", err)
			}
		})
	}
}

func TestCfgPersistentSpecialMountsUsesSnapshotterHandoffWithoutApplicationPVCMount(t *testing.T) {
	podsDir := t.TempDir()
	handoffDir := t.TempDir()
	containerID := "container-id"
	spec, pvcRoot := persistentSpecialTestSpec(t, podsDir, "pod-uid", "containers/app")
	spec.Mounts = nil
	writePersistentSpecialHandoff(t, handoffDir, containerID, persistentSpecialHandoff{
		Version:       persistentSpecialHandoffVer,
		SnapshotKey:   containerID,
		PodUID:        "pod-uid",
		ContainerName: "app",
		VolumeName:    "rootfs",
		PVCMountPath:  pvcRoot,
	})

	if err := cfgPersistentSpecialMountsWithHandoffAt(spec, podsDir, handoffDir, containerID); err != nil {
		t.Fatal(err)
	}
	if len(spec.Mounts) != 7 {
		t.Fatalf("got %d mounts, want 7: %#v", len(spec.Mounts), spec.Mounts)
	}
	for _, mount := range spec.Mounts {
		if strings.HasPrefix(mount.Destination, rootfsSpecialMountBase) {
			t.Fatalf("handoff mount leaked into final spec: %#v", mount)
		}
		if !strings.HasPrefix(mount.Source, filepath.Join(pvcRoot, "containers/app/special")+string(filepath.Separator)) {
			t.Fatalf("persistent mount source is outside PVC special directory: %#v", mount)
		}
	}
}

func TestCfgPersistentSpecialMountsFailsClosedWithoutPVCSource(t *testing.T) {
	podsDir := t.TempDir()
	spec, _ := persistentSpecialTestSpec(t, podsDir, "pod-uid", "containers/app")
	spec.Mounts = nil

	err := cfgPersistentSpecialMountsWithHandoffAt(spec, podsDir, t.TempDir(), "container-id")
	if err == nil || !strings.Contains(err.Error(), "PVC source is unavailable") {
		t.Fatalf("error = %v, want unavailable PVC source", err)
	}
}

func TestCfgPersistentSpecialMountsRejectsMismatchedHandoff(t *testing.T) {
	podsDir := t.TempDir()
	handoffDir := t.TempDir()
	containerID := "container-id"
	spec, pvcRoot := persistentSpecialTestSpec(t, podsDir, "pod-uid", "containers/app")
	spec.Mounts = nil
	writePersistentSpecialHandoff(t, handoffDir, containerID, persistentSpecialHandoff{
		Version:       persistentSpecialHandoffVer,
		SnapshotKey:   containerID,
		PodUID:        "other-pod",
		ContainerName: "app",
		VolumeName:    "rootfs",
		PVCMountPath:  pvcRoot,
	})

	_, _, err := resolvePersistentSpecialConfigWithHandoff(spec, podsDir, handoffDir, containerID)
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("error = %v, want handoff mismatch", err)
	}
}

func TestCfgPersistentSpecialMountsRejectsUnsafeHandoffPermissions(t *testing.T) {
	podsDir := t.TempDir()
	handoffDir := t.TempDir()
	containerID := "container-id"
	spec, pvcRoot := persistentSpecialTestSpec(t, podsDir, "pod-uid", "containers/app")
	spec.Mounts = nil
	writePersistentSpecialHandoff(t, handoffDir, containerID, persistentSpecialHandoff{
		Version:       persistentSpecialHandoffVer,
		SnapshotKey:   containerID,
		PodUID:        "pod-uid",
		ContainerName: "app",
		VolumeName:    "rootfs",
		PVCMountPath:  pvcRoot,
	})
	sum := sha256.Sum256([]byte(containerID))
	path := filepath.Join(handoffDir, hex.EncodeToString(sum[:])+".json")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}

	_, _, err := resolvePersistentSpecialConfigWithHandoff(spec, podsDir, handoffDir, containerID)
	if err == nil || !strings.Contains(err.Error(), "unsafe permissions") {
		t.Fatalf("error = %v, want unsafe permissions", err)
	}
}

func TestResolvePersistentSpecialConfigRejectsInvalidContract(t *testing.T) {
	podsDir := t.TempDir()
	tests := []struct {
		name   string
		mutate func(*specs.Spec)
		want   string
	}{
		{
			name: "unexpected reserved mount",
			mutate: func(spec *specs.Spec) {
				spec.Mounts[0].Destination = filepath.Join(rootfsSpecialMountBase, "other")
			},
			want: "exactly one hidden PVC mount",
		},
		{
			name: "duplicate hidden mount",
			mutate: func(spec *specs.Spec) {
				spec.Mounts = append(spec.Mounts, spec.Mounts[0])
			},
			want: "found 2",
		},
		{
			name: "wrong pod uid",
			mutate: func(spec *specs.Spec) {
				spec.Annotations[kubernetesSandboxUIDAnno] = "another-pod"
			},
			want: "does not belong to Pod UID",
		},
		{
			name: "escaping layer path",
			mutate: func(spec *specs.Spec) {
				spec.Annotations[rootfsRwLayerAnnotation] = `[{"name":"app","volumeName":"rootfs","path":"../escape","persistentSpecialMounts":true}]`
			},
			want: "must not escape",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec, _ := persistentSpecialTestSpec(t, podsDir, "pod-"+strings.ReplaceAll(test.name, " ", "-"), "app")
			test.mutate(spec)
			_, _, err := resolvePersistentSpecialConfig(spec, podsDir)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestResolvePersistentSpecialConfigRejectsSymlinkLayerPath(t *testing.T) {
	podsDir := t.TempDir()
	spec, pvcRoot := persistentSpecialTestSpec(t, podsDir, "pod-uid", "linked/child")
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(pvcRoot, "linked")); err != nil {
		t.Fatal(err)
	}
	_, _, err := resolvePersistentSpecialConfig(spec, podsDir)
	if err == nil || !strings.Contains(err.Error(), "contains a symlink") {
		t.Fatalf("error = %v, want symlink rejection", err)
	}
}

func TestResolvePersistentSpecialConfigUsesCustomDestinations(t *testing.T) {
	podsDir := t.TempDir()
	spec, _ := persistentSpecialTestSpec(t, podsDir, "pod-uid", "app")
	if err := os.MkdirAll(filepath.Join(spec.Root.Path, "etc/docker"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(spec.Root.Path, "etc/docker/daemon.json"), []byte("{\n  \"data-root\": \"/docker-data\"\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(spec.Root.Path, "etc/rancher/k3s"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(spec.Root.Path, "etc/rancher/k3s/config.yaml"), []byte("data-dir: /k3s-data\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(spec.Root.Path, "etc/rancher/rke2"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(spec.Root.Path, "etc/rancher/rke2/config.yaml"), []byte("data-dir: /rke2-data\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	config, enabled, err := resolvePersistentSpecialConfig(spec, podsDir)
	if err != nil || !enabled {
		t.Fatalf("resolve config: enabled=%v err=%v", enabled, err)
	}
	want := map[string]string{"docker": "/docker-data", "k3s": "/k3s-data", "rke2": "/rke2-data"}
	for _, mapping := range config.mappings {
		if destination, found := want[mapping.Name]; found && mapping.Destination != destination {
			t.Fatalf("mapping %s destination = %q, want %q", mapping.Name, mapping.Destination, destination)
		}
		delete(want, mapping.Name)
	}
	if len(want) != 0 {
		t.Fatalf("custom destinations not preserved: %#v", config.mappings)
	}
}

func TestInitializePersistentSpecialMountsRejectsInvalidPaths(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, specialRoot, dockerPath string)
	}{
		{
			name: "symlink",
			mutate: func(t *testing.T, _ string, dockerPath string) {
				if err := os.Remove(dockerPath); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(t.TempDir(), dockerPath); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "parent symlink",
			mutate: func(t *testing.T, specialRoot, _ string) {
				varLib := filepath.Join(specialRoot, "var/lib")
				if err := os.RemoveAll(varLib); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(t.TempDir(), varLib); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "regular file",
			mutate: func(t *testing.T, _ string, dockerPath string) {
				if err := os.Remove(dockerPath); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(dockerPath, []byte("invalid"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			podsDir := t.TempDir()
			spec, _ := persistentSpecialTestSpec(t, podsDir, "pod-uid", "app")
			config, _, err := resolvePersistentSpecialConfig(spec, podsDir)
			if err != nil {
				t.Fatal(err)
			}
			if err := initializePersistentSpecialMounts(spec, config); err != nil {
				t.Fatal(err)
			}
			dockerPath := filepath.Join(config.specialRoot, "var/lib/docker")
			test.mutate(t, config.specialRoot, dockerPath)
			if err := initializePersistentSpecialMounts(spec, config); err == nil {
				t.Fatal("expected invalid special path error")
			}
		})
	}
}

func TestInitializePersistentSpecialMountsUsesChangedDestination(t *testing.T) {
	podsDir := t.TempDir()
	spec, _ := persistentSpecialTestSpec(t, podsDir, "pod-uid", "app")
	config, _, err := resolvePersistentSpecialConfig(spec, podsDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := initializePersistentSpecialMounts(spec, config); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(spec.Root.Path, "etc/docker"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(spec.Root.Path, "etc/docker/daemon.json"), []byte("{\n  \"data-root\": \"/docker-data\"\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, _, err := resolvePersistentSpecialConfig(spec, podsDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := initializePersistentSpecialMounts(spec, changed); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(filepath.Join(changed.specialRoot, "docker-data")); err != nil || !info.IsDir() {
		t.Fatalf("custom docker special path not created: %v", err)
	}
	for _, mapping := range changed.mappings {
		if mapping.Name == "docker" && mapping.Destination != "/docker-data" {
			t.Fatalf("docker destination = %q", mapping.Destination)
		}
	}
}

func TestResolvePersistentSpecialConfigRejectsOverlappingDestinations(t *testing.T) {
	podsDir := t.TempDir()
	spec, _ := persistentSpecialTestSpec(t, podsDir, "pod-uid", "app")
	if err := os.MkdirAll(filepath.Join(spec.Root.Path, "etc/docker"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(spec.Root.Path, "etc/docker/daemon.json"), []byte("{\n  \"data-root\": \"/var/lib\"\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := resolvePersistentSpecialConfig(spec, podsDir); err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("overlap error = %v", err)
	}
}
