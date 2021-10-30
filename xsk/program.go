package xsk

import (
	"time"

	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
)

// Only support Little Endian
// production use
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2" xsk ./bpf/xsk.c
// test use
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2" xsk ./bpf/xsk_test_icmp.c

// Program based on the attached rx queue.
type Program struct {
	Program *ebpf.Program
	Sockets *ebpf.Map
}

// Attach the XDP Program to an interface.
func (p *Program) Attach(Ifindex int) error {
	if err := removeProgram(Ifindex); err != nil {
		return err
	}
	return attachProgram(Ifindex, p.Program)
}

// Detach the XDP Program from an interface.
func (p *Program) Detach(Ifindex int) error {
	return removeProgram(Ifindex)
}

// Register adds the socket file descriptor to map.
func (p *Program) Register(queueID int, fd int) error {
	if err := p.Sockets.Put(uint32(queueID), uint32(fd)); err != nil {
		return err
	}

	return nil
}

// Unregister removes the socket file descriptor from map.
func (p *Program) Unregister(queueID int) error {
	if err := p.Sockets.Delete(uint32(queueID)); err != nil {
		return err
	}
	return nil
}

// Close closes and frees the resources allocated for the Program.
func (p *Program) Close() error {
	var allErrors []error
	if p.Sockets != nil {
		if err := p.Sockets.Close(); err != nil {
			allErrors = append(allErrors, err)
		}
		p.Sockets = nil
	}

	if p.Program != nil {
		if err := p.Program.Close(); err != nil {
			allErrors = append(allErrors, err)
		}
		p.Program = nil
	}

	if len(allErrors) > 0 {
		return allErrors[0]
	}
	return nil
}

func NewProgram() (*Program, error) {
	var objs xskObjects
	if err := loadXskObjects(&objs, nil); err != nil {
		return nil, errors.Wrap(err, "load xsk objects failed")
	}

	return &Program{Program: objs.XskProgram, Sockets: objs.XsksMap}, nil
}

// removeProgram removes an existing XDP program from the given network interface.
func removeProgram(Ifindex int) error {
	var link netlink.Link
	var err error
	link, err = netlink.LinkByIndex(Ifindex)
	if err != nil {
		return errors.Wrap(err, "get link by index failed")
	}
	if !isXdpAttached(link) {
		return nil
	}
	if err = netlink.LinkSetXdpFd(link, -1); err != nil {
		return errors.Wrap(err, "netlink.LinkSetXdpFd(link, -1) failed")
	}
	for {
		link, err = netlink.LinkByIndex(Ifindex)
		if err != nil {
			return errors.Wrap(err, "get link by index failed")
		}
		if !isXdpAttached(link) {
			break
		}
		time.Sleep(time.Second)
	}
	return nil
}

func isXdpAttached(link netlink.Link) bool {
	if link.Attrs() != nil && link.Attrs().Xdp != nil && link.Attrs().Xdp.Attached {
		return true
	}
	return false
}

// attachProgram attaches the given XDP program to the network interface.
func attachProgram(Ifindex int, program *ebpf.Program) error {
	link, err := netlink.LinkByIndex(Ifindex)
	if err != nil {
		return errors.Wrap(err, "get link by index failed")
	}

	if err = netlink.LinkSetXdpFdWithFlags(link, program.FD(), int(DefaultXdpFlags)); err != nil {
		return errors.Wrap(err, "netlink.LinkSetXdpFdWithFlags set failed")
	}

	return nil
}
