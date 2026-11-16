package sysbox

import (
	"strings"
	"testing"
)

func TestRegisterRejectsInvalidResourceCacheTTL(t *testing.T) {
	for _, value := range []string{"0", "-1s", "invalid", "100"} {
		fs := &Fs{PreReg: true}
		if err := fs.Register(&FsRegInfo{ResourceCacheTTL: value}); err == nil || !strings.Contains(err.Error(), "sysbox/resource-cache-ttl") {
			t.Fatalf("TTL %q: %v", value, err)
		}
	}
}
