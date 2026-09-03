package systemd

import (
	"path/filepath"
	"testing"

	"github.com/opencontainers/runc/libcontainer/configs"
)

func TestNestedIdentityUnifiedChildCgroupPath(t *testing.T) {
	m := &unifiedManager{cgroups: &configs.Cgroup{NestedIdentity: true}, path: "/sys/fs/cgroup/l2-limit"}
	want := filepath.Join(m.path, "sysbox.delegate", "init.scope")
	if got := m.GetChildCgroupPaths()[""]; got != want {
		t.Fatalf("child cgroup path = %q, want %q", got, want)
	}
}
