package ebpf

import (
	"os"
	"testing"

	"github.com/cilium/ebpf/asm"
	"golang.org/x/sys/unix"
)

// Use an empty, disposable cgroup so the test never changes workload access.
func TestDeviceFilterAttachDetach(t *testing.T) {
	if os.Getenv("SYSBOX_RECOVERY_PRIVILEGED") != "1" {
		t.Skip("requires writable cgroup v2 and BPF privileges")
	}
	dir, err := os.MkdirTemp("/sys/fs/cgroup", "sysbox-device-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(dir)
	fd, err := unix.Open(dir, unix.O_DIRECTORY|unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	detach, err := LoadAttachCgroupDeviceFilter(asm.Instructions{asm.Mov.Imm(asm.R0, 1), asm.Return()}, "GPL", fd)
	if err != nil {
		t.Fatal(err)
	}
	if err := detach(); err != nil {
		t.Fatal(err)
	}
}
