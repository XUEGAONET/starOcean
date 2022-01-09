package underlay

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"starOcean/utils/binary"
)

type Program struct {
	program         *ebpf.Program
	mapXsk          *ebpf.Map
	mapRedirectIPv6 *ebpf.Map
	mapRedirectPort *ebpf.Map
}

func (p *Program) GetProgram() *ebpf.Program {
	return p.program
}

func (p *Program) GetMapXsk() *ebpf.Map {
	return p.mapXsk
}

func (p *Program) RegisterIPv6(addr net.IP) error {
	if len(addr) != net.IPv6len {
		return fmt.Errorf("invalid ipv6 address length")
	}

	err := p.mapRedirectIPv6.Put(addr, uint8(1))
	if err != nil {
		return err
	}

	return nil
}

func (p *Program) UnregisterIPv6(addr net.IP) error {
	if len(addr) != net.IPv6len {
		return fmt.Errorf("invalid ipv6 address length")
	}

	err := p.mapRedirectIPv6.Delete(addr)
	if err != nil {
		return err
	}

	return nil
}

func (p *Program) RegisterPort(port uint16) error {
	err := p.mapRedirectPort.Put(binary.Swap16(port), uint8(1))
	if err != nil {
		return err
	}

	return nil
}

func (p *Program) UnregisterPort(port uint16) error {
	err := p.mapRedirectPort.Delete(binary.Swap16(port))
	if err != nil {
		return err
	}

	return nil
}

func (p *Program) Close() error {
	if p.mapXsk != nil {
		err := p.mapXsk.Close()
		if err != nil {
			return err
		}
		p.mapXsk = nil
	}

	if p.mapRedirectIPv6 != nil {
		err := p.mapRedirectIPv6.Close()
		if err != nil {
			return err
		}
		p.mapRedirectIPv6 = nil
	}

	if p.mapRedirectPort != nil {
		err := p.mapRedirectPort.Close()
		if err != nil {
			return err
		}
		p.mapRedirectPort = nil
	}

	if p.program != nil {
		err := p.program.Close()
		if err != nil {
			return err
		}
		p.program = nil
	}

	return nil
}

func NewProgram() (*Program, error) {
	var objs ebpfObjects
	err := loadEbpfObjects(&objs, nil)
	if err != nil {
		return nil, err
	}

	return &Program{
		program:         objs.XskUnderlay,
		mapXsk:          objs.XsksMap,
		mapRedirectIPv6: objs.RedirectIpv6,
		mapRedirectPort: objs.RedirectPort,
	}, nil
}
