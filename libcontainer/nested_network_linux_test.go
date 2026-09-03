//go:build linux
// +build linux

package libcontainer

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestNestedNetworkPath(t *testing.T) {
	for _, path := range []string{"/run/netns/cni-test", "/var/run/netns/cni-test"} {
		if !hasPathPrefix(path, "/run/netns") && !hasPathPrefix(path, "/var/run/netns") {
			t.Fatalf("managed path %q was rejected", path)
		}
	}
	for _, path := range []string{"/run/netns", "/run/netns/../host", "/proc/1/ns/net", "run/netns/cni-test"} {
		if hasPathPrefix(path, "/run/netns") || hasPathPrefix(path, "/var/run/netns") {
			t.Fatalf("unsafe path %q was accepted", path)
		}
	}
}

type nestedLinkHandleFake struct {
	link      netlink.Link
	lookupErr error
	setUpErr  error
	setUp     int
}

func (h *nestedLinkHandleFake) LinkByName(name string) (netlink.Link, error) {
	if name != "lo" {
		return nil, errors.New("unexpected link name")
	}
	return h.link, h.lookupErr
}

func (h *nestedLinkHandleFake) LinkSetUp(netlink.Link) error {
	h.setUp++
	return h.setUpErr
}

func TestEnableNestedLoopback(t *testing.T) {
	for _, tc := range []struct {
		name        string
		flags       net.Flags
		setUpErr    error
		wantSetUp   int
		wantErrText string
	}{
		{name: "down", wantSetUp: 1},
		{name: "already up", flags: unix.IFF_UP},
		{name: "set up failure", setUpErr: errors.New("denied"), wantSetUp: 1, wantErrText: "enable child network namespace loopback"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attrs := netlink.NewLinkAttrs()
			attrs.Name = "lo"
			attrs.Flags = tc.flags
			handle := &nestedLinkHandleFake{link: &netlink.Dummy{LinkAttrs: attrs}, setUpErr: tc.setUpErr}
			err := enableNestedLoopback(handle)
			if handle.setUp != tc.wantSetUp {
				t.Fatalf("LinkSetUp calls: got %d, want %d", handle.setUp, tc.wantSetUp)
			}
			if tc.wantErrText == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErrText != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErrText)) {
				t.Fatalf("error %v does not contain %q", err, tc.wantErrText)
			}
		})
	}
}

func TestRestoreNestedRouteOrder(t *testing.T) {
	routes := []netlink.Route{
		{Gw: net.ParseIP("10.0.0.1")},
		{},
	}
	sortNestedRoutes(routes)
	if len(routes[0].Gw) != 0 || len(routes[1].Gw) == 0 {
		t.Fatal("gateway route was not ordered after its direct route")
	}
}
