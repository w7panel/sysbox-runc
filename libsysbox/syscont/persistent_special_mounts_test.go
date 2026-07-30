//go:build linux
// +build linux

package syscont

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/opencontainers/runtime-spec/specs-go"
)

func persistentSpecialTestSpec(t *testing.T, podsDir, podUID, layerPath string) (*specs.Spec, string) {
	t.Helper()
	pvcRoot := filepath.Join(podsDir, podUID, "volumes", "kubernetes.io~csi", "pvc-test", "mount")
	if err := os.MkdirAll(pvcRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	rootfs := t.TempDir()
	for _, path := range []string{
		"var/lib/docker",
		"var/lib/rancher/k3s/agent",
		"var/lib/containerd/io.containerd.snapshotter.v1.overlayfs",
	} {
		if err := os.MkdirAll(filepath.Join(rootfs, path), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	raw := `[{"name":"app","volumeName":"rootfs","path":"` + layerPath + `"}]`
	return &specs.Spec{
		Root: &specs.Root{Path: rootfs},
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
		kubernetesContainerNameAnno: "app",
	}
	if err := cfgPersistentSpecialMountsAt(spec, t.TempDir()); err != nil {
		t.Fatal(err)
	}
}

func TestCfgPersistentSpecialMountsSkipsPodSandbox(t *testing.T) {
	spec := &specs.Spec{Annotations: map[string]string{
		rootfsRwLayerAnnotation: `[{"name":"app","volumeName":"rootfs","path":"app"}]`,
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
	copyCount := 0
	copyDir := func(source, destination string) error {
		copyCount++
		return os.WriteFile(filepath.Join(destination, "from-image"), []byte(source), 0o644)
	}
	config, enabled, err := resolvePersistentSpecialConfig(spec, podsDir)
	if err != nil || !enabled {
		t.Fatalf("resolve config: enabled=%v err=%v", enabled, err)
	}
	if err := initializePersistentSpecial(spec, config, copyDir); err != nil {
		t.Fatal(err)
	}
	if copyCount != 3 {
		t.Fatalf("copied %d image directories, want 3", copyCount)
	}
	for _, mapping := range config.meta.Mappings {
		if _, err := os.Stat(filepath.Join(config.specialRoot, mapping.Name, "from-image")); err != nil {
			t.Fatalf("mapping %s not initialized: %v", mapping.Name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(config.specialRoot, "meta.json")); err != nil {
		t.Fatalf("metadata was not written: %v", err)
	}

	if err := initializePersistentSpecial(spec, config, func(string, string) error {
		return errors.New("copy must not run when metadata matches")
	}); err != nil {
		t.Fatalf("reuse failed: %v", err)
	}

	if err := cfgPersistentSpecialMountsAt(spec, podsDir); err != nil {
		t.Fatal(err)
	}
	if len(spec.Mounts) != 3 {
		t.Fatalf("got %d mounts, want 3: %#v", len(spec.Mounts), spec.Mounts)
	}
	for index, mapping := range config.meta.Mappings {
		mount := spec.Mounts[index]
		if mount.Source != filepath.Join(pvcRoot, "containers/app/special", mapping.Name) ||
			mount.Destination != mapping.Destination || mount.Type != "bind" ||
			!reflect.DeepEqual(mount.Options, []string{"rbind", "rprivate"}) {
			t.Fatalf("unexpected persistent mount: %#v", mount)
		}
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
	config, enabled, err := resolvePersistentSpecialConfig(spec, podsDir)
	if err != nil || !enabled {
		t.Fatalf("resolve config: enabled=%v err=%v", enabled, err)
	}
	if config.meta.Mappings[0].Destination != "/docker-data" || config.meta.Mappings[1].Destination != "/k3s-data/agent" {
		t.Fatalf("custom destinations not preserved: %#v", config.meta.Mappings)
	}
}

func TestInitializePersistentSpecialFailsClosedAndCleansStaging(t *testing.T) {
	podsDir := t.TempDir()
	spec, _ := persistentSpecialTestSpec(t, podsDir, "pod-uid", "app")
	config, _, err := resolvePersistentSpecialConfig(spec, podsDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := initializePersistentSpecial(spec, config, func(string, string) error { return errors.New("copy failed") }); err == nil {
		t.Fatal("expected initialization failure")
	}
	if _, err := os.Stat(config.specialRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("special directory exists after failed initialization: %v", err)
	}
	staging, err := filepath.Glob(filepath.Join(config.layerRoot, ".special.staging-*"))
	if err != nil || len(staging) != 0 {
		t.Fatalf("staging directory was not cleaned: %#v err=%v", staging, err)
	}

	if err := os.Mkdir(config.specialRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := initializePersistentSpecial(spec, config, func(string, string) error { return nil }); err == nil || !strings.Contains(err.Error(), "without valid metadata") {
		t.Fatalf("unmarked directory error = %v", err)
	}
}
