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
		"var/lib/rancher/k3s/agent",
		"var/lib/rancher/rke2",
		"var/lib/buildkit",
		"var/lib/containerd/io.containerd.snapshotter.v1.overlayfs",
	} {
		if err := os.MkdirAll(filepath.Join(rootfs, path), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	raw := `[{"name":"app","volumeName":"rootfs","path":"` + layerPath + `"}]`
	return &specs.Spec{
		Root: &specs.Root{Path: rootfs},
		Linux: &specs.Linux{
			UIDMappings: []specs.LinuxIDMapping{{ContainerID: 0, HostID: 100000, Size: 65536}},
			GIDMappings: []specs.LinuxIDMapping{{ContainerID: 0, HostID: 200000, Size: 65536}},
		},
		Annotations: map[string]string{
			rootfsRwLayerAnnotation:     raw,
			persistentSpecialAnnotation: "true",
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
	delete(spec.Annotations, persistentSpecialAnnotation)
	original := append([]specs.Mount(nil), spec.Mounts...)

	if err := cfgPersistentSpecialMountsAt(spec, podsDir); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(spec.Mounts, original) {
		t.Fatalf("mounts changed without explicit opt-in: %#v", spec.Mounts)
	}

	spec.Annotations[persistentSpecialAnnotation] = "false"
	if err := cfgPersistentSpecialMountsAt(spec, podsDir); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(spec.Mounts, original) {
		t.Fatalf("mounts changed with opt-in disabled: %#v", spec.Mounts)
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
		rootfsRwLayerAnnotation:     `[{"name":"other","volumeName":"rootfs","path":"other"}]`,
		persistentSpecialAnnotation: "true",
		kubernetesContainerNameAnno: "app",
	}
	if err := cfgPersistentSpecialMountsAt(spec, t.TempDir()); err != nil {
		t.Fatal(err)
	}
}

func TestCfgPersistentSpecialMountsSkipsPodSandbox(t *testing.T) {
	spec := &specs.Spec{Annotations: map[string]string{
		rootfsRwLayerAnnotation:     `[{"name":"app","volumeName":"rootfs","path":"app"}]`,
		persistentSpecialAnnotation: "true",
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
	if err := initializePersistentUpperMounts(spec, config); err != nil {
		t.Fatal(err)
	}
	for _, mapping := range config.mappings {
		source, err := persistentUpperMountSource(config, mapping)
		if err != nil {
			t.Fatal(err)
		}
		if info, err := os.Stat(source); err != nil || !info.IsDir() {
			t.Fatalf("mapping %s not initialized: %v", mapping.Name, err)
		}
	}
	dockerSource := filepath.Join(config.upperRoot, "var/lib/docker")
	if data, err := os.ReadFile(filepath.Join(dockerSource, "from-image")); err != nil || string(data) != "preloaded" {
		t.Fatalf("image preload = %q err=%v", data, err)
	}
	if err := os.WriteFile(filepath.Join(dockerSource, "persistent"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(spec.Root.Path, "var/lib/docker/after-first"), []byte("new-image-data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := initializePersistentUpperMounts(spec, config); err != nil {
		t.Fatalf("reuse failed: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(dockerSource, "persistent")); err != nil || string(data) != "data" {
		t.Fatalf("persistent data = %q err=%v", data, err)
	}
	if _, err := os.Stat(filepath.Join(dockerSource, "after-first")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("existing PVC directory was re-seeded: %v", err)
	}
	if _, err := os.Stat(filepath.Join(config.layerRoot, "special")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("special directory err = %v, want not exist", err)
	}

	if err := cfgPersistentSpecialMountsAt(spec, podsDir); err != nil {
		t.Fatal(err)
	}
	if len(spec.Mounts) != 7 {
		t.Fatalf("got %d mounts, want 7: %#v", len(spec.Mounts), spec.Mounts)
	}
	for index, mapping := range config.mappings {
		mount := spec.Mounts[index]
		wantSource := filepath.Join(pvcRoot, "containers/app/upper", strings.TrimPrefix(mapping.Destination, "/"))
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

func TestInitializePersistentUpperMountsCreatesEmptyDirectoryForMissingImagePath(t *testing.T) {
	rootfs := t.TempDir()
	upperRoot := filepath.Join(t.TempDir(), "upper")
	spec := &specs.Spec{Root: &specs.Root{Path: rootfs}}
	config := persistentSpecialConfig{
		layerRoot: filepath.Dir(upperRoot),
		upperRoot: upperRoot,
		mappings:  []persistentSpecialMapping{{Name: "missing", Destination: "/var/lib/missing"}},
	}
	if err := initializePersistentUpperMounts(spec, config); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(upperRoot, "var/lib/missing")
	entries, err := os.ReadDir(destination)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("missing image path initialized with entries: %#v", entries)
	}
}

func TestInitializePersistentUpperMountsRejectsInvalidImageSource(t *testing.T) {
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
			upperRoot := filepath.Join(t.TempDir(), "upper")
			spec := &specs.Spec{Root: &specs.Root{Path: rootfs}}
			config := persistentSpecialConfig{
				layerRoot: filepath.Dir(upperRoot),
				upperRoot: upperRoot,
				mappings:  []persistentSpecialMapping{{Name: "docker", Destination: "/var/lib/docker"}},
			}
			if err := initializePersistentUpperMounts(spec, config); err == nil {
				t.Fatal("expected invalid image source error")
			}
			if _, err := os.Stat(filepath.Join(upperRoot, "var/lib/docker")); !errors.Is(err, os.ErrNotExist) {
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
		if !strings.HasPrefix(mount.Source, filepath.Join(pvcRoot, "containers/app/upper")+string(filepath.Separator)) {
			t.Fatalf("persistent mount source is outside PVC upper directory: %#v", mount)
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
				spec.Annotations[rootfsRwLayerAnnotation] = `[{"name":"app","volumeName":"rootfs","path":"../escape"}]`
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
	want := map[string]string{"docker": "/docker-data", "k3s-agent": "/k3s-data/agent", "rke2": "/rke2-data"}
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

func TestInitializePersistentUpperMountsRejectsInvalidPaths(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, upperRoot, dockerPath string)
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
			mutate: func(t *testing.T, upperRoot, _ string) {
				varLib := filepath.Join(upperRoot, "var/lib")
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
			if err := initializePersistentUpperMounts(spec, config); err != nil {
				t.Fatal(err)
			}
			dockerPath := filepath.Join(config.upperRoot, "var/lib/docker")
			test.mutate(t, config.upperRoot, dockerPath)
			if err := initializePersistentUpperMounts(spec, config); err == nil {
				t.Fatal("expected invalid upper path error")
			}
		})
	}
}

func TestInitializePersistentUpperMountsUsesChangedDestination(t *testing.T) {
	podsDir := t.TempDir()
	spec, _ := persistentSpecialTestSpec(t, podsDir, "pod-uid", "app")
	config, _, err := resolvePersistentSpecialConfig(spec, podsDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := initializePersistentUpperMounts(spec, config); err != nil {
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
	if err := initializePersistentUpperMounts(spec, changed); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(filepath.Join(changed.upperRoot, "docker-data")); err != nil || !info.IsDir() {
		t.Fatalf("custom docker upper path not created: %v", err)
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
