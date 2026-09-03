package sysbox

import (
	"testing"

	ipcLib "github.com/nestybox/sysbox-ipc/sysboxMgrLib"
)

func TestSetMappingMode(t *testing.T) {
	mgr := NewMgr("test", true)
	if err := mgr.SetMappingMode("nested-identity"); err != nil {
		t.Fatal(err)
	}
	if mgr.MappingMode != ipcLib.NestedIdentity {
		t.Fatalf("mapping mode = %d", mgr.MappingMode)
	}
	if err := mgr.SetMappingMode("auto"); err == nil {
		t.Fatal("invalid mapping mode accepted")
	}
}
