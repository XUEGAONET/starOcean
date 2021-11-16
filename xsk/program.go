// Copyright 2019 Asavie Technologies Ltd. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package xsk

import (
	"time"

	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
)

// Program based on the attached rx queue.
type Program struct {
	Program          *ebpf.Program
	MapSockets       *ebpf.Map
	MapIngressFilter *ebpf.Map
	MapLocalArpTable *ebpf.Map
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

func (p *Program) Close() error {
	if p.Program != nil {
		if err := p.Program.Close(); err != nil {
			return err
		}
		p.Program = nil
	}

	return nil
}

func NewProgram() (*Program, error) {
	var objs xskObjects
	if err := loadXskObjects(&objs, nil); err != nil {
		return nil, errors.Wrap(err, "load xsk objects failed")
	}

	return &Program{
		Program:          objs.XskProgram,
		MapSockets:       objs.XsksMap,
		MapIngressFilter: objs.IngressFilter,
		MapLocalArpTable: objs.LocalArpTable,
	}, nil
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
