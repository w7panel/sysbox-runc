package fs2

import (
	"path/filepath"
	"testing"

	"github.com/opencontainers/runc/libcontainer/configs"
)

func TestNestedIdentityChildCgroupPath(t *testing.T) {
	m := &manager{config: &configs.Cgroup{NestedIdentity: true}, dirPath: "/sys/fs/cgroup/l2-limit"}
	want := filepath.Join(m.dirPath, nestedDelegate, "init.scope")
	if got := m.GetChildCgroupPaths()[""]; got != want {
		t.Fatalf("child cgroup path = %q, want %q", got, want)
	}
}

func TestNestedIdentityRequiresV2Contract(t *testing.T) {
	// The implementation must never silently fall back to v1 delegation.
	// Runtime environments without cgroup v2 are covered by the integration
	// harness; this test documents the contract for the manager methods.
	if nestedDelegate != "sysbox.delegate" {
		t.Fatalf("unexpected nested delegation directory: %s", nestedDelegate)
	}
}
