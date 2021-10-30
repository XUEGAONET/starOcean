package layers

import (
	"net"
	"unsafe"
)

type EthernetType uint16

const (
	EthernetTypeIPv4                        EthernetType = 0x0800
	EthernetTypeARP                         EthernetType = 0x0806
	EthernetTypeIPv6                        EthernetType = 0x86DD
	EthernetTypeCiscoDiscovery              EthernetType = 0x2000
	EthernetTypeNortelDiscovery             EthernetType = 0x01a2
	EthernetTypeTransparentEthernetBridging EthernetType = 0x6558
	EthernetTypeDot1Q                       EthernetType = 0x8100
	EthernetTypePPP                         EthernetType = 0x880b
	EthernetTypePPPoEDiscovery              EthernetType = 0x8863
	EthernetTypePPPoESession                EthernetType = 0x8864
	EthernetTypeMPLSUnicast                 EthernetType = 0x8847
	EthernetTypeMPLSMulticast               EthernetType = 0x8848
	EthernetTypeEAPOL                       EthernetType = 0x888e
	EthernetTypeERSPAN                      EthernetType = 0x88be
	EthernetTypeQinQ                        EthernetType = 0x88a8
	EthernetTypeLinkLayerDiscovery          EthernetType = 0x88cc
	EthernetTypeEthernetCTP                 EthernetType = 0x9000
)

// Ethernet is the layer for Ethernet frame headers.
// [0:6] is SrcMAC, [6:12] is DstMAC
// [12:14] is EthernetType

type Ethernet []byte

func (e *Ethernet) GetSrcAddress() net.HardwareAddr {
	t := (*e)[0:6]
	return *(*net.HardwareAddr)(&t)
}

func (e *Ethernet) GetDstAddress() net.HardwareAddr {
	t := (*e)[6:12]
	return *(*net.HardwareAddr)(&t)
}

func (e *Ethernet) GetEthernetType() uint16 {
	return *(*uint16)(unsafe.Pointer(&(*e)[12]))
}

func (e *Ethernet) SetSrcAddress(addr net.HardwareAddr) {
	copy((*e)[0:6], addr[0:6])
}

func (e *Ethernet) SetDstAddress(addr net.HardwareAddr) {
	copy((*e)[6:12], addr[0:6])
}

func (e *Ethernet) SetEthernetType(typ uint16) {
	(*e)[12] = (*(*[2]byte)(unsafe.Pointer(&typ)))[0]
	(*e)[13] = (*(*[2]byte)(unsafe.Pointer(&typ)))[1]
}
