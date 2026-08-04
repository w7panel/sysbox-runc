//go:build linux

package syscont

import (
	"os"
	"path/filepath"
	"testing"

	sh "github.com/nestybox/sysbox-libs/idShiftUtils"
	"github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

func testVolumeInitSpec(rootfs, source, annotation string) *specs.Spec {
	return &specs.Spec{
		Root:  &specs.Root{Path: rootfs},
		Linux: &specs.Linux{},
		Annotations: map[string]string{
			kubernetesContainerNameAnno: "app",
			kubernetesSandboxUIDAnno:    "pod-uid",
			volumeInitAnnotation:        annotation,
		},
		Mounts: []specs.Mount{{Source: source, Destination: "/data", Type: "bind", Options: []string{"rw"}}},
	}
}

func TestInitializePVCVolumesSeedsEmptyVolumeAndPreservesData(t *testing.T) {
	podsDir := t.TempDir()
	rootfs := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rootfs, "data", "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootfs, "data", "nested", "image.txt"), []byte("from-image"), 0o640); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(podsDir, "pod-uid", "volumes", "kubernetes.io~csi", "data", "mount")
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatal(err)
	}
	spec := testVolumeInitSpec(rootfs, source, `[{"name":"app","volumeName":"data","mountPath":"/data"}]`)

	if err := initializePVCVolumesAt(spec, podsDir, sh.IDMappedMount, false); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(source, "nested", "image.txt"))
	if err != nil || string(content) != "from-image" {
		t.Fatalf("unexpected initialized content %q, err=%v", content, err)
	}
	if err := os.WriteFile(filepath.Join(source, "nested", "image.txt"), []byte("persistent"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := initializePVCVolumesAt(spec, podsDir, sh.IDMappedMount, false); err != nil {
		t.Fatal(err)
	}
	content, err = os.ReadFile(filepath.Join(source, "nested", "image.txt"))
	if err != nil || string(content) != "persistent" {
		t.Fatalf("existing PVC content was overwritten: %q, err=%v", content, err)
	}
}

func TestInitializePVCVolumesAcceptsKubeletPVCSourceName(t *testing.T) {
	podsDir := t.TempDir()
	rootfs := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rootfs, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootfs, "data", "image.txt"), []byte("from-image"), 0o644); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(podsDir, "pod-uid", "volumes", "kubernetes.io~csi", "pvc-123", "mount")
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatal(err)
	}
	spec := testVolumeInitSpec(rootfs, source, `[{"name":"app","volumeName":"webroot","mountPath":"/data"}]`)

	if err := initializePVCVolumesAt(spec, podsDir, sh.IDMappedMount, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(source, "image.txt")); err != nil {
		t.Fatal(err)
	}
}

func TestInitializePVCVolumesTreatsLostFoundAsEmpty(t *testing.T) {
	podsDir := t.TempDir()
	rootfs := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rootfs, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootfs, "data", "image.txt"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(podsDir, "pod-uid", "volumes", "kubernetes.io~csi", "data", "mount")
	if err := os.MkdirAll(filepath.Join(source, "lost+found"), 0o700); err != nil {
		t.Fatal(err)
	}
	spec := testVolumeInitSpec(rootfs, source, `[{"name":"app","volumeName":"data","mountPath":"/data"}]`)

	if err := initializePVCVolumesAt(spec, podsDir, sh.IDMappedMount, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(source, "image.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(source, "lost+found")); err != nil {
		t.Fatal("lost+found must be preserved")
	}
}

func TestInitializePVCVolumesSupportsDirectorySubPath(t *testing.T) {
	podsDir := t.TempDir()
	rootfs := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rootfs, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootfs, "data", "image.txt"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(podsDir, "pod-uid", "volume-subpaths", "data", "app", "0")
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatal(err)
	}
	spec := testVolumeInitSpec(rootfs, source, `[{"name":"app","volumeName":"data","mountPath":"/data"}]`)

	if err := initializePVCVolumesAt(spec, podsDir, sh.IDMappedMount, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(source, "image.txt")); err != nil {
		t.Fatal(err)
	}
}

func TestInitializePVCVolumesSkipsFileMount(t *testing.T) {
	podsDir := t.TempDir()
	rootfs := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rootfs, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(podsDir, "pod-uid", "volume-subpaths", "data", "app", "0")
	if err := os.MkdirAll(filepath.Dir(source), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("existing-file"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec := testVolumeInitSpec(rootfs, source, `[{"name":"app","volumeName":"data","mountPath":"/data"}]`)

	if err := initializePVCVolumesAt(spec, podsDir, sh.IDMappedMount, false); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(source)
	if err != nil || string(content) != "existing-file" {
		t.Fatalf("file mount changed: %q, err=%v", content, err)
	}
}

func TestInitializePVCVolumesFirstContainerWinsSharedVolume(t *testing.T) {
	podsDir := t.TempDir()
	source := filepath.Join(podsDir, "pod-uid", "volumes", "kubernetes.io~csi", "data", "mount")
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatal(err)
	}
	firstRootfs := t.TempDir()
	if err := os.MkdirAll(filepath.Join(firstRootfs, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(firstRootfs, "data", "first.txt"), []byte("first"), 0o644); err != nil {
		t.Fatal(err)
	}
	first := testVolumeInitSpec(firstRootfs, source, `[{"name":"app","volumeName":"data","mountPath":"/data"}]`)
	if err := initializePVCVolumesAt(first, podsDir, sh.IDMappedMount, false); err != nil {
		t.Fatal(err)
	}

	secondRootfs := t.TempDir()
	if err := os.MkdirAll(filepath.Join(secondRootfs, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secondRootfs, "data", "second.txt"), []byte("second"), 0o644); err != nil {
		t.Fatal(err)
	}
	second := testVolumeInitSpec(secondRootfs, source, `[{"name":"sidecar","volumeName":"data","mountPath":"/data"}]`)
	second.Annotations[kubernetesContainerNameAnno] = "sidecar"
	if err := initializePVCVolumesAt(second, podsDir, sh.IDMappedMount, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(source, "first.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(source, "second.txt")); !os.IsNotExist(err) {
		t.Fatalf("second container overwrote shared PVC: %v", err)
	}
}

func TestInitializePVCVolumesSkipsFileImagePath(t *testing.T) {
	podsDir := t.TempDir()
	rootfs := t.TempDir()
	if err := os.WriteFile(filepath.Join(rootfs, "data"), []byte("image-file"), 0o644); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(podsDir, "pod-uid", "volumes", "kubernetes.io~csi", "data", "mount")
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatal(err)
	}
	spec := testVolumeInitSpec(rootfs, source, `[{"name":"app","volumeName":"data","mountPath":"/data"}]`)

	if err := initializePVCVolumesAt(spec, podsDir, sh.IDMappedMount, false); err != nil {
		t.Fatal(err)
	}
	empty, err := pvcVolumeEmpty(source)
	if err != nil || !empty {
		t.Fatalf("PVC changed for file image path: empty=%v err=%v", empty, err)
	}
}

func TestInitializePVCVolumesRejectsSourceFromAnotherPod(t *testing.T) {
	podsDir := t.TempDir()
	rootfs := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rootfs, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(podsDir, "other-pod", "volumes", "kubernetes.io~csi", "data", "mount")
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatal(err)
	}
	spec := testVolumeInitSpec(rootfs, source, `[{"name":"app","volumeName":"data","mountPath":"/data"}]`)

	if err := initializePVCVolumesAt(spec, podsDir, sh.IDMappedMount, false); err == nil {
		t.Fatal("expected source validation error")
	}
}

func TestInitializePVCVolumesSkipsPodSandbox(t *testing.T) {
	spec := &specs.Spec{
		Root:        &specs.Root{Path: t.TempDir()},
		Linux:       &specs.Linux{},
		Annotations: map[string]string{volumeInitAnnotation: `[{"name":"app","volumeName":"data","mountPath":"/data"}]`},
	}
	if err := initializePVCVolumesAt(spec, t.TempDir(), sh.IDMappedMount, false); err != nil {
		t.Fatalf("Pod sandbox must ignore volume initialization metadata: %v", err)
	}
}

func TestInitializePVCVolumesDoesNotRequireIDMapForNonEmptyVolume(t *testing.T) {
	podsDir := t.TempDir()
	rootfs := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rootfs, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(podsDir, "pod-uid", "volumes", "kubernetes.io~csi", "data", "mount")
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "persistent.txt"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec := testVolumeInitSpec(rootfs, source, `[{"name":"app","volumeName":"data","mountPath":"/data"}]`)

	if err := initializePVCVolumesAt(spec, podsDir, sh.Shiftfs, true); err != nil {
		t.Fatalf("non-empty PVC must skip initialization without checking idmapped mounts: %v", err)
	}
}

func TestInitializePVCVolumesRequiresIDMapWhenCopying(t *testing.T) {
	podsDir := t.TempDir()
	rootfs := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rootfs, "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootfs, "data", "image.txt"), []byte("copy"), 0o644); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(podsDir, "pod-uid", "volumes", "kubernetes.io~csi", "data", "mount")
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatal(err)
	}
	spec := testVolumeInitSpec(rootfs, source, `[{"name":"app","volumeName":"data","mountPath":"/data"}]`)

	if err := initializePVCVolumesAt(spec, podsDir, sh.Shiftfs, true); err == nil {
		t.Fatal("empty PVC initialization must fail without idmapped mounts")
	}
	if _, err := os.Stat(filepath.Join(source, "image.txt")); !os.IsNotExist(err) {
		t.Fatalf("PVC was modified before idmapped validation: %v", err)
	}
}

func TestInitializePVCVolumesStoresCanonicalIDsWithoutChangingImageRootfs(t *testing.T) {
	podsDir := t.TempDir()
	rootfs := t.TempDir()
	imageDir := filepath.Join(rootfs, "data")
	if err := os.MkdirAll(imageDir, 0o755); err != nil {
		t.Fatal(err)
	}
	imageFile := filepath.Join(imageDir, "owned.txt")
	if err := os.WriteFile(imageFile, []byte("owned"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(imageFile, 100000, 100000); err != nil {
		t.Skipf("test environment cannot create shifted ownership: %v", err)
	}
	source := filepath.Join(podsDir, "pod-uid", "volumes", "kubernetes.io~csi", "data", "mount")
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatal(err)
	}
	spec := testVolumeInitSpec(rootfs, source, `[{"name":"app","volumeName":"data","mountPath":"/data"}]`)
	spec.Linux.UIDMappings = []specs.LinuxIDMapping{{ContainerID: 0, HostID: 100000, Size: 65536}}
	spec.Linux.GIDMappings = []specs.LinuxIDMapping{{ContainerID: 0, HostID: 100000, Size: 65536}}

	if err := initializePVCVolumesAt(spec, podsDir, sh.IDMappedMount, false); err != nil {
		t.Fatal(err)
	}
	var imageStat, pvcStat unix.Stat_t
	if err := unix.Stat(imageFile, &imageStat); err != nil {
		t.Fatal(err)
	}
	if err := unix.Stat(filepath.Join(source, "owned.txt"), &pvcStat); err != nil {
		t.Fatal(err)
	}
	if imageStat.Uid != 100000 || imageStat.Gid != 100000 {
		t.Fatalf("image rootfs ownership changed: %d:%d", imageStat.Uid, imageStat.Gid)
	}
	if pvcStat.Uid != 0 || pvcStat.Gid != 0 {
		t.Fatalf("PVC must store canonical IDs, got %d:%d", pvcStat.Uid, pvcStat.Gid)
	}
}
