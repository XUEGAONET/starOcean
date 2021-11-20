// Copyright 2019 Asavie Technologies Ltd. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package xsk

import (
	"fmt"
	"net"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"starOcean/utils/binary"
)

// Program based on the attached rx queue.
type Program struct {
	program          *ebpf.Program
	mapSockets       *ebpf.Map
	mapIngressFilter *ebpf.Map
	mapLocalArpTable *ebpf.Map
}

// Attach the XDP Program to an interface.
func (p *Program) Attach(Ifindex int) error {
	if err := removeProgram(Ifindex); err != nil {
		return err
	}
	return attachProgram(Ifindex, p.program)
}

// Detach the XDP Program from an interface.
func (p *Program) Detach(Ifindex int) error {
	return removeProgram(Ifindex)
}

// Register adds the socket file descriptor to map.
func (p *Program) RegisterFD(queueID int, fd int) error {
	if err := p.mapSockets.Put(uint32(queueID), uint32(fd)); err != nil {
		return err
	}

	return nil
}

// Unregister removes the socket file descriptor from map.
func (p *Program) UnregisterFD(queueID int) error {
	if err := p.mapSockets.Delete(uint32(queueID)); err != nil {
		return err
	}
	return nil
}

// RegisterIngressFilter 设置简易ACL规则。protocol 仅支持 unix.IPPROTO_TCP 或者 unix.IPPROTO_UDP，
// port 为允许的目标端口号
func (p *Program) RegisterIngressFilter(protocol int, port int) error {
	if protocol != unix.IPPROTO_TCP && protocol != unix.IPPROTO_UDP {
		return fmt.Errorf("invalid protocol")
	}

	key := uint32(protocol)
	key += uint32(binary.Swap16(uint16(port))) << 16

	err := p.mapIngressFilter.Put(key, uint8(1))
	if err != nil {
		return fmt.Errorf("put ingress filter record failed: %v", err)
	}

	return nil
}

// UnregisterIngressFilter 删除已设置的简易ACL规则。protocol 仅支持 unix.IPPROTO_TCP 或者 unix.IPPROTO_UDP，
// port 为允许的目标端口号
func (p *Program) UnregisterIngressFilter(protocol int, port int) error {
	if protocol != unix.IPPROTO_TCP && protocol != unix.IPPROTO_UDP {
		return fmt.Errorf("invalid protocol")
	}

	key := uint32(protocol)
	key += uint32(binary.Swap16(uint16(port))) << 16

	err := p.mapIngressFilter.Delete(key)
	if err != nil {
		return fmt.Errorf("delete ingress filter record failed: %v", err)
	}

	return nil
}

func (p *Program) RegisterLocalArp(addr net.IP, mac net.HardwareAddr) error {
	ip := addr.To4()
	if ip == nil {
		return fmt.Errorf("parse local address v4 failed")
	}

	key := *(*uint32)(unsafe.Pointer(&ip[0]))
	err := p.mapLocalArpTable.Put(key, mac[:6])
	if err != nil {
		return fmt.Errorf("put local arp record failed: %v", err)
	}

	return nil
}

func (p *Program) UnregisterLocalArp(addr net.IP) error {
	ip := addr.To4()
	if ip == nil {
		return fmt.Errorf("parse local address v4 failed")
	}

	key := *(*uint32)(unsafe.Pointer(&ip[0]))
	err := p.mapLocalArpTable.Delete(key)
	if err != nil {
		return fmt.Errorf("delete local arp record failed: %v", err)
	}

	return nil
}

func (p *Program) Close() error {
	var allErrors []error = nil

	if p.mapSockets != nil {
		if err := p.mapSockets.Close(); err != nil {
			allErrors = append(allErrors, err)
		}
		p.mapSockets = nil
	}

	if p.mapIngressFilter != nil {
		if err := p.mapIngressFilter.Close(); err != nil {
			allErrors = append(allErrors, err)
		}
		p.mapIngressFilter = nil
	}

	if p.mapLocalArpTable != nil {
		if err := p.mapLocalArpTable.Close(); err != nil {
			allErrors = append(allErrors, err)
		}
		p.mapLocalArpTable = nil
	}

	if p.program != nil {
		if err := p.program.Close(); err != nil {
			return err
		}
		p.program = nil
	}

	return nil
}

func NewProgram() (*Program, error) {
	var objs xskObjects
	if err := loadXskObjects(&objs, nil); err != nil {
		return nil, errors.Wrap(err, "load xsk objects failed")
	}

	return &Program{
		program:          objs.XskProgram,
		mapSockets:       objs.XsksMap,
		mapIngressFilter: objs.IngressFilter,
		mapLocalArpTable: objs.LocalArpTable,
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
