package layers

import (
	"net"
	"unsafe"
)

const (
	EthernetTypeIPv4                        uint16 = 0x0800
	EthernetTypeARP                         uint16 = 0x0806
	EthernetTypeIPv6                        uint16 = 0x86DD
	EthernetTypeCiscoDiscovery              uint16 = 0x2000
	EthernetTypeNortelDiscovery             uint16 = 0x01a2
	EthernetTypeTransparentEthernetBridging uint16 = 0x6558
	EthernetTypeDot1Q                       uint16 = 0x8100
	EthernetTypePPP                         uint16 = 0x880b
	EthernetTypePPPoEDiscovery              uint16 = 0x8863
	EthernetTypePPPoESession                uint16 = 0x8864
	EthernetTypeMPLSUnicast                 uint16 = 0x8847
	EthernetTypeMPLSMulticast               uint16 = 0x8848
	EthernetTypeEAPOL                       uint16 = 0x888e
	EthernetTypeERSPAN                      uint16 = 0x88be
	EthernetTypeQinQ                        uint16 = 0x88a8
	EthernetTypeLinkLayerDiscovery          uint16 = 0x88cc
	EthernetTypeEthernetCTP                 uint16 = 0x9000
)

// Ethernet is the layer for Ethernet frame headers.
// [0:6] is DstMAC, [6:12] is SrcMAC
// [12:14] is EthernetType

type Ethernet []byte

const LengthEthernet = 14

func (e *Ethernet) GetSrcAddress() net.HardwareAddr {
	t := (*e)[6:12]
	return *(*net.HardwareAddr)(&t)
}

func (e *Ethernet) GetDstAddress() net.HardwareAddr {
	t := (*e)[0:6]
	return *(*net.HardwareAddr)(&t)
}

func (e *Ethernet) GetEthernetType() uint16 {
	return *(*uint16)(unsafe.Pointer(&(*e)[12]))
}

func (e *Ethernet) SetSrcAddress(addr net.HardwareAddr) {
	copy((*e)[6:12], addr[0:6])
}

func (e *Ethernet) SetDstAddress(addr net.HardwareAddr) {
	copy((*e)[0:6], addr[0:6])
}

func (e *Ethernet) SetEthernetType(typ uint16) {
	(*e)[12] = (*(*[2]byte)(unsafe.Pointer(&typ)))[0]
	(*e)[13] = (*(*[2]byte)(unsafe.Pointer(&typ)))[1]
}
