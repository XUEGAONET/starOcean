package bpf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
)

type Linker interface {
	GetProgram() *ebpf.Program
}

func DetachProgram(Ifindex int) error {
	link, err := netlink.LinkByIndex(Ifindex)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("get link %d failed", Ifindex))
	}

	if !isXdpAttached(link) {
		return nil
	}

	err = netlink.LinkSetXdpFd(link, -1)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("detach from %d failed", Ifindex))
	}

	return nil
}

func isXdpAttached(link netlink.Link) bool {
	if link.Attrs() != nil {
		if link.Attrs().Xdp != nil {
			return link.Attrs().Xdp.Attached
		}
	}

	return false
}

func AttachProgram(Ifindex int, program Linker, xdpFlags int) error {
	link, err := netlink.LinkByIndex(Ifindex)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("get link %d failed", Ifindex))
	}

	err = netlink.LinkSetXdpFdWithFlags(link, program.GetProgram().FD(), xdpFlags)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("attach from %d failed", Ifindex))
	}

	return nil
}
