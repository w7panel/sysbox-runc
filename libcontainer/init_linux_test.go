//go:build linux
// +build linux

package libcontainer

import (
	"testing"

	"github.com/opencontainers/runc/libcontainer/configs"
)

func TestShouldCloseInternalFds(t *testing.T) {
	tests := []struct {
		name   string
		config configs.Config
		want   bool
	}{
		{name: "standard", want: true},
		{
			name:   "legacy skip special mounts",
			config: configs.Config{SkipSpecialMounts: true},
			want:   false,
		},
		{
			name: "nested identity",
			config: configs.Config{
				SkipSpecialMounts: true,
				NestedIdentity:    true,
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldCloseInternalFds(&tt.config); got != tt.want {
				t.Fatalf("shouldCloseInternalFds() = %v, want %v", got, tt.want)
			}
		})
	}
}
