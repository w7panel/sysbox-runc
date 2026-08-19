//go:build linux
// +build linux

package libcontainer

import (
	"errors"
	"testing"

	"github.com/opencontainers/runc/libcontainer/configs"
	"golang.org/x/sys/unix"
)

func TestMountNestedProcfs(t *testing.T) {
	tests := []struct {
		name            string
		newMountErr     error
		legacyMountErr  error
		wantErr         error
		wantLegacyCalls int
	}{
		{name: "new mount API succeeds"},
		{name: "EPERM falls back", newMountErr: unix.EPERM, wantLegacyCalls: 1},
		{name: "other error does not fall back", newMountErr: unix.EINVAL, wantErr: unix.EINVAL},
		{name: "fallback error is returned", newMountErr: unix.EPERM, legacyMountErr: unix.EACCES, wantErr: unix.EACCES, wantLegacyCalls: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			legacyCalls := 0
			m := &configs.Mount{
				Source: "proc",
				Device: "proc",
				Flags:  unix.MS_NOSUID | unix.MS_NOEXEC,
				Data:   "hidepid=0",
			}
			err := mountNestedProcfs(
				m,
				"/proc",
				func(target, fsType string, flags int, data string) error {
					if target != "/proc" || fsType != "proc" || flags != unix.MS_NOSUID || data != "hidepid=0" {
						t.Fatalf("unexpected new mount arguments: target=%q fsType=%q flags=%#x data=%q", target, fsType, flags, data)
					}
					return tt.newMountErr
				},
				func(source, target, fsType string, flags uintptr, data string) error {
					legacyCalls++
					if source != "proc" || target != "/proc" || fsType != "proc" || flags != unix.MS_NOSUID || data != "hidepid=0" {
						t.Fatalf("unexpected legacy mount arguments: source=%q target=%q fsType=%q flags=%#x data=%q", source, target, fsType, flags, data)
					}
					return tt.legacyMountErr
				},
			)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("mountNestedProcfs() error = %v, want %v", err, tt.wantErr)
			}
			if legacyCalls != tt.wantLegacyCalls {
				t.Fatalf("legacy mount calls = %d, want %d", legacyCalls, tt.wantLegacyCalls)
			}
		})
	}
}

func TestNeedsSetupDev(t *testing.T) {
	config := &configs.Config{
		Mounts: []*configs.Mount{
			{
				Device:      "bind",
				Source:      "/dev",
				Destination: "/dev",
			},
		},
	}
	if needsSetupDev(config) {
		t.Fatal("expected needsSetupDev to be false, got true")
	}
}

func TestNeedsSetupDevStrangeSource(t *testing.T) {
	config := &configs.Config{
		Mounts: []*configs.Mount{
			{
				Device:      "bind",
				Source:      "/devx",
				Destination: "/dev",
			},
		},
	}
	if needsSetupDev(config) {
		t.Fatal("expected needsSetupDev to be false, got true")
	}
}

func TestNeedsSetupDevStrangeDest(t *testing.T) {
	config := &configs.Config{
		Mounts: []*configs.Mount{
			{
				Device:      "bind",
				Source:      "/dev",
				Destination: "/devx",
			},
		},
	}
	if !needsSetupDev(config) {
		t.Fatal("expected needsSetupDev to be true, got false")
	}
}

func TestNeedsSetupDevStrangeSourceDest(t *testing.T) {
	config := &configs.Config{
		Mounts: []*configs.Mount{
			{
				Device:      "bind",
				Source:      "/devx",
				Destination: "/devx",
			},
		},
	}
	if !needsSetupDev(config) {
		t.Fatal("expected needsSetupDev to be true, got false")
	}
}

func TestMntDestDependsOn(t *testing.T) {
	tests := []struct {
		dest  string
		prior string
		want  bool
	}{
		{"/run", "/run", true},
		{"/run/secrets/kubernetes.io/serviceaccount", "/run", true},
		{"/run/foo", "/run/foo/bar", false},
		{"/runfoo", "/run", false},
		{"/var/run", "/run", false},
		{"/run", "/", true},
		{"/", "/", true},
	}
	for _, tc := range tests {
		if got := mntDestDependsOn(tc.dest, tc.prior); got != tc.want {
			t.Errorf("mntDestDependsOn(%q, %q) = %v, want %v", tc.dest, tc.prior, got, tc.want)
		}
	}
}
