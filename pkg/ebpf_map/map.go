package ebpf_map

import (
	"fmt"
	"net"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"starOcean/utils/binary"
)

func PutLocalArpRecord(ebpfMap *ebpf.Map, ip4 string, mac string) error {
	if ebpfMap == nil {
		return fmt.Errorf("invalid map")
	}

	parsedIP4 := net.ParseIP(ip4).To4()
	if parsedIP4 == nil {
		return fmt.Errorf("parse ipv4 address failed")
	}
	parsedMAC, err := net.ParseMAC(mac)
	if err != nil {
		return fmt.Errorf("parse mac address failed: %v", err)
	}

	key := *(*uint32)(unsafe.Pointer(&parsedIP4[0]))

	err = ebpfMap.Put(key, parsedMAC[:6])
	if err != nil {
		return fmt.Errorf("put local arp record failed: %v", err)
	}

	return nil
}

func DeleteLocalArpRecord(ebpfMap *ebpf.Map, ip4 string) error {
	if ebpfMap == nil {
		return fmt.Errorf("invalid map")
	}

	parsedIP4 := net.ParseIP(ip4).To4()
	if parsedIP4 == nil {
		return fmt.Errorf("parse ipv4 address failed")
	}

	key := *(*uint32)(unsafe.Pointer(&parsedIP4[0]))

	err := ebpfMap.Delete(key)
	if err != nil {
		return fmt.Errorf("delete local arp record failed: %v", err)
	}

	return nil
}

func PutIngressFilterRecord(ebpfMap *ebpf.Map, protocol string, dstPort uint16) error {
	if ebpfMap == nil {
		return fmt.Errorf("invalid map")
	}

	key := uint32(0)
	switch strings.ToLower(protocol) {
	case "tcp":
		key = unix.IPPROTO_TCP
	case "udp":
		key = unix.IPPROTO_UDP
	default:
		return fmt.Errorf("parse protocol failed")
	}

	key += uint32(binary.Swap16(dstPort)) << 16

	err := ebpfMap.Put(key, uint8(1))
	if err != nil {
		return fmt.Errorf("put ingress filter record failed: %v", err)
	}

	return nil
}

func DeleteIngressFilterRecord(ebpfMap *ebpf.Map, protocol string, dstPort uint16) error {
	if ebpfMap == nil {
		return fmt.Errorf("invalid map")
	}

	key := uint32(0)
	switch strings.ToLower(protocol) {
	case "tcp":
		key = unix.IPPROTO_TCP
	case "udp":
		key = unix.IPPROTO_UDP
	default:
		return fmt.Errorf("parse protocol failed")
	}

	key += uint32(binary.Swap16(dstPort)) << 16

	err := ebpfMap.Delete(key)
	if err != nil {
		return fmt.Errorf("delete ingress filter record failed: %v", err)
	}

	return nil
}
