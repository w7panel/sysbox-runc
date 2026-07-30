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
	copyCount := 0
	copyDir := func(source, destination string, uidMappings, gidMappings []specs.LinuxIDMapping) error {
		copyCount++
		if !reflect.DeepEqual(uidMappings, spec.Linux.UIDMappings) || !reflect.DeepEqual(gidMappings, spec.Linux.GIDMappings) {
			t.Fatalf("copy mappings = %#v/%#v", uidMappings, gidMappings)
		}
		return os.WriteFile(filepath.Join(destination, "from-image"), []byte(source), 0o644)
	}
	config, enabled, err := resolvePersistentSpecialConfig(spec, podsDir)
	if err != nil || !enabled {
		t.Fatalf("resolve config: enabled=%v err=%v", enabled, err)
	}
	if err := initializePersistentSpecial(spec, config, copyDir); err != nil {
		t.Fatal(err)
	}
	if copyCount != 7 {
		t.Fatalf("copied %d image directories, want 7", copyCount)
	}
	for _, mapping := range config.meta.Mappings {
		if _, err := os.Stat(filepath.Join(config.specialRoot, mapping.Name, "from-image")); err != nil {
			t.Fatalf("mapping %s not initialized: %v", mapping.Name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(config.specialRoot, "meta.json")); err != nil {
		t.Fatalf("metadata was not written: %v", err)
	}

	if err := initializePersistentSpecial(spec, config, func(string, string, []specs.LinuxIDMapping, []specs.LinuxIDMapping) error {
		return errors.New("copy must not run when metadata matches")
	}); err != nil {
		t.Fatalf("reuse failed: %v", err)
	}

	if err := cfgPersistentSpecialMountsAt(spec, podsDir); err != nil {
		t.Fatal(err)
	}
	if len(spec.Mounts) != 7 {
		t.Fatalf("got %d mounts, want 7: %#v", len(spec.Mounts), spec.Mounts)
	}
	for index, mapping := range config.meta.Mappings {
		mount := spec.Mounts[index]
		if mount.Source != filepath.Join(pvcRoot, "containers/app/special", mapping.Name) ||
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
	for _, mapping := range config.meta.Mappings {
		if destination, found := want[mapping.Name]; found && mapping.Destination != destination {
			t.Fatalf("mapping %s destination = %q, want %q", mapping.Name, mapping.Destination, destination)
		}
		delete(want, mapping.Name)
	}
	if len(want) != 0 {
		t.Fatalf("custom destinations not preserved: %#v", config.meta.Mappings)
	}
}

func TestInitializePersistentSpecialRejectsLegacyMetadata(t *testing.T) {
	podsDir := t.TempDir()
	spec, _ := persistentSpecialTestSpec(t, podsDir, "pod-uid", "app")
	config, _, err := resolvePersistentSpecialConfig(spec, podsDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := initializePersistentSpecial(spec, config, func(string, string, []specs.LinuxIDMapping, []specs.LinuxIDMapping) error { return nil }); err != nil {
		t.Fatal(err)
	}
	legacy := []byte(`{"version":2,"mappings":[{"name":"docker","destination":"/var/lib/docker"}]}`)
	if err := os.WriteFile(filepath.Join(config.specialRoot, "meta.json"), legacy, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := initializePersistentSpecial(spec, config, func(string, string, []specs.LinuxIDMapping, []specs.LinuxIDMapping) error { return nil }); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("legacy metadata error = %v", err)
	}
}

func TestPersistentSpecialRsyncIDMapNormalizesHostIDs(t *testing.T) {
	ids := map[uint32]struct{}{42: {}, 100000: {}, 100007: {}, 200003: {}}
	mappings := []specs.LinuxIDMapping{
		{ContainerID: 0, HostID: 100000, Size: 65536},
		{ContainerID: 65536, HostID: 200000, Size: 1024},
	}
	got, err := persistentSpecialRsyncIDMap(ids, mappings)
	if err != nil {
		t.Fatal(err)
	}
	if want := "100000:0,100007:7,200003:65539"; got != want {
		t.Fatalf("ID map = %q, want %q", got, want)
	}
}

func TestPersistentSpecialRsyncIDMapKeepsContainerIDs(t *testing.T) {
	ids := map[uint32]struct{}{0: {}, 7: {}, 65534: {}}
	mappings := []specs.LinuxIDMapping{{ContainerID: 0, HostID: 100000, Size: 65536}}
	got, err := persistentSpecialRsyncIDMap(ids, mappings)
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Fatalf("ID map = %q, want empty", got)
	}
}

func TestPersistentSpecialRsyncIDMapsScansSource(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "file"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("file", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	mapping := []specs.LinuxIDMapping{{ContainerID: 123, HostID: 0, Size: 1}}
	uidMap, gidMap, err := persistentSpecialRsyncIDMaps(root, mapping, mapping)
	if err != nil {
		t.Fatal(err)
	}
	if uidMap != "0:123" || gidMap != "0:123" {
		t.Fatalf("ID maps = %q/%q, want 0:123/0:123", uidMap, gidMap)
	}
}

func TestPersistentSpecialContainerIDRejectsInvalidMappings(t *testing.T) {
	tests := []struct {
		name    string
		mapping specs.LinuxIDMapping
	}{
		{name: "zero size", mapping: specs.LinuxIDMapping{HostID: 100000}},
		{name: "host overflow", mapping: specs.LinuxIDMapping{HostID: ^uint32(0), Size: 2}},
		{name: "container overflow", mapping: specs.LinuxIDMapping{ContainerID: ^uint32(0), HostID: 100000, Size: 2}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := persistentSpecialContainerID(test.mapping.HostID, []specs.LinuxIDMapping{test.mapping}); err == nil {
				t.Fatal("expected invalid mapping error")
			}
		})
	}
}

func TestInitializePersistentSpecialFailsClosedAndCleansStaging(t *testing.T) {
	podsDir := t.TempDir()
	spec, _ := persistentSpecialTestSpec(t, podsDir, "pod-uid", "app")
	config, _, err := resolvePersistentSpecialConfig(spec, podsDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := initializePersistentSpecial(spec, config, func(string, string, []specs.LinuxIDMapping, []specs.LinuxIDMapping) error {
		return errors.New("copy failed")
	}); err == nil {
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
	if err := initializePersistentSpecial(spec, config, func(string, string, []specs.LinuxIDMapping, []specs.LinuxIDMapping) error { return nil }); err == nil || !strings.Contains(err.Error(), "without valid metadata") {
		t.Fatalf("unmarked directory error = %v", err)
	}
}
