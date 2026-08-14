//go:build linux
// +build linux

package libcontainer

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

type nestedLinkState struct {
	name   string
	up     bool
	addrs  []netlink.Addr
	routes []netlink.Route
}

type nestedLinkHandle interface {
	LinkByName(string) (netlink.Link, error)
	LinkSetUp(netlink.Link) error
}

func setupNestedNetwork(sourcePath string, targetPid int) error {
	path := filepath.Clean(sourcePath)
	if !filepath.IsAbs(path) || (!hasPathPrefix(path, "/run/netns") && !hasPathPrefix(path, "/var/run/netns")) {
		return fmt.Errorf("nested network source %q is outside the managed netns directory", sourcePath)
	}

	sourceNs, err := netns.GetFromPath(path)
	if err != nil {
		return err
	}
	defer sourceNs.Close()
	targetNs, err := netns.GetFromPid(targetPid)
	if err != nil {
		return err
	}
	defer targetNs.Close()

	source, err := netlink.NewHandleAt(sourceNs)
	if err != nil {
		return err
	}
	defer source.Delete()
	target, err := netlink.NewHandleAt(targetNs)
	if err != nil {
		return err
	}
	defer target.Delete()
	if err := enableNestedLoopback(target); err != nil {
		return err
	}

	states, err := captureNestedLinks(source)
	if err != nil {
		return err
	}
	if len(states) == 0 {
		return errors.New("CNI network namespace has no non-loopback interface")
	}

	moved := make([]nestedLinkState, 0, len(states))
	for _, state := range states {
		link, err := source.LinkByName(state.name)
		if err != nil {
			rollbackNestedLinks(target, sourceNs, source, moved)
			return err
		}
		if err := source.LinkSetNsFd(link, int(targetNs)); err != nil {
			rollbackNestedLinks(target, sourceNs, source, moved)
			return fmt.Errorf("move interface %s: %w", state.name, err)
		}
		moved = append(moved, state)
	}
	if err := restoreNestedLinks(target, moved); err != nil {
		rollbackNestedLinks(target, sourceNs, source, moved)
		return err
	}
	if err := replaceNetnsMount(path, sourceNs, targetNs); err != nil {
		rollbackNestedLinks(target, sourceNs, source, moved)
		return err
	}
	return nil
}

func enableNestedLoopback(handle nestedLinkHandle) error {
	loopback, err := handle.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("find child network namespace loopback: %w", err)
	}
	if loopback.Attrs() != nil && loopback.Attrs().Flags&unix.IFF_UP != 0 {
		return nil
	}
	if err := handle.LinkSetUp(loopback); err != nil {
		return fmt.Errorf("enable child network namespace loopback: %w", err)
	}
	return nil
}

func hasPathPrefix(path, prefix string) bool {
	rel, err := filepath.Rel(prefix, path)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func captureNestedLinks(handle *netlink.Handle) ([]nestedLinkState, error) {
	links, err := handle.LinkList()
	if err != nil {
		return nil, err
	}
	states := make([]nestedLinkState, 0, len(links))
	for _, link := range links {
		attrs := link.Attrs()
		if attrs == nil || attrs.Name == "lo" {
			continue
		}
		addrs, err := handle.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			return nil, err
		}
		routes, err := handle.RouteList(link, netlink.FAMILY_ALL)
		if err != nil {
			return nil, err
		}
		states = append(states, nestedLinkState{
			name:   attrs.Name,
			up:     attrs.Flags&unix.IFF_UP != 0,
			addrs:  addrs,
			routes: routes,
		})
	}
	return states, nil
}

func restoreNestedLinks(handle *netlink.Handle, states []nestedLinkState) error {
	for _, state := range states {
		link, err := handle.LinkByName(state.name)
		if err != nil {
			return err
		}
		for i := range state.addrs {
			if err := handle.AddrReplace(link, &state.addrs[i]); err != nil {
				return fmt.Errorf("restore address on %s: %w", state.name, err)
			}
		}
		if state.up {
			if err := handle.LinkSetUp(link); err != nil {
				return fmt.Errorf("restore interface %s state: %w", state.name, err)
			}
		}
		sortNestedRoutes(state.routes)
		for i := range state.routes {
			state.routes[i].LinkIndex = link.Attrs().Index
			if err := handle.RouteReplace(&state.routes[i]); err != nil {
				return fmt.Errorf("restore route on %s: %w", state.name, err)
			}
		}
	}
	return nil
}

func sortNestedRoutes(routes []netlink.Route) {
	sort.SliceStable(routes, func(i, j int) bool {
		return len(routes[i].Gw) == 0 && len(routes[j].Gw) != 0
	})
}

func rollbackNestedLinks(from *netlink.Handle, target netns.NsHandle, to *netlink.Handle, states []nestedLinkState) {
	for _, state := range states {
		if link, err := from.LinkByName(state.name); err == nil {
			_ = from.LinkSetNsFd(link, int(target))
		}
	}
	_ = restoreNestedLinks(to, states)
}

func replaceNetnsMount(path string, oldNs, newNs netns.NsHandle) error {
	if err := unix.Unmount(path, unix.MNT_DETACH); err != nil {
		return fmt.Errorf("unmount original CNI netns handle: %w", err)
	}
	newSource := fmt.Sprintf("/proc/self/fd/%d", int(newNs))
	if err := unix.Mount(newSource, path, "", unix.MS_BIND, ""); err == nil {
		return nil
	} else {
		oldSource := fmt.Sprintf("/proc/self/fd/%d", int(oldNs))
		if restoreErr := unix.Mount(oldSource, path, "", unix.MS_BIND, ""); restoreErr != nil {
			return fmt.Errorf("bind child netns: %v (restore original handle: %v)", err, restoreErr)
		}
		return fmt.Errorf("bind child netns: %w", err)
	}
}
