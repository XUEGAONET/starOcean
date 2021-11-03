package layers

import (
	"unsafe"
)

const (
	ARPRequest uint16 = 0x0001
	ARPReply   uint16 = 0x0002
)

const (
	// According to pcap-linktype(7) and http://www.tcpdump.org/linktypes.html
	LinkTypeNull           uint16 = 0
	LinkTypeEthernet       uint16 = 1
	LinkTypeAX25           uint16 = 3
	LinkTypeTokenRing      uint16 = 6
	LinkTypeArcNet         uint16 = 7
	LinkTypeSLIP           uint16 = 8
	LinkTypePPP            uint16 = 9
	LinkTypeFDDI           uint16 = 10
	LinkTypePPP_HDLC       uint16 = 50
	LinkTypePPPEthernet    uint16 = 51
	LinkTypeATM_RFC1483    uint16 = 100
	LinkTypeRaw            uint16 = 101
	LinkTypeC_HDLC         uint16 = 104
	LinkTypeIEEE802_11     uint16 = 105
	LinkTypeFRelay         uint16 = 107
	LinkTypeLoop           uint16 = 108
	LinkTypeLinuxSLL       uint16 = 113
	LinkTypeLTalk          uint16 = 114
	LinkTypePFLog          uint16 = 117
	LinkTypePrismHeader    uint16 = 119
	LinkTypeIPOverFC       uint16 = 122
	LinkTypeSunATM         uint16 = 123
	LinkTypeIEEE80211Radio uint16 = 127
	LinkTypeARCNetLinux    uint16 = 129
	LinkTypeIPOver1394     uint16 = 138
	LinkTypeMTP2Phdr       uint16 = 139
	LinkTypeMTP2           uint16 = 140
	LinkTypeMTP3           uint16 = 141
	LinkTypeSCCP           uint16 = 142
	LinkTypeDOCSIS         uint16 = 143
	LinkTypeLinuxIRDA      uint16 = 144
	LinkTypeLinuxLAPD      uint16 = 177
	LinkTypeLinuxUSB       uint16 = 220
	LinkTypeFC2            uint16 = 224
	LinkTypeFC2Framed      uint16 = 225
	LinkTypeIPv4           uint16 = 228
	LinkTypeIPv6           uint16 = 229
)

type ARP []byte

const LengthARP = 8

func (a *ARP) GetLinkType() uint16 {
	return *(*uint16)(unsafe.Pointer(&((*a)[0])))
}

func (a *ARP) SetLinkType(u uint16) {
	(*a)[0] = (*(*[2]byte)(unsafe.Pointer(&u)))[0]
	(*a)[1] = (*(*[2]byte)(unsafe.Pointer(&u)))[1]
}

func (a *ARP) GetProtocolType() uint16 {
	return *(*uint16)(unsafe.Pointer(&((*a)[2])))
}

func (a *ARP) SetProtocolType(u uint16) {
	(*a)[2] = (*(*[2]byte)(unsafe.Pointer(&u)))[0]
	(*a)[3] = (*(*[2]byte)(unsafe.Pointer(&u)))[1]
}

func (a *ARP) GetLinkAddressLength() uint8 {
	return *&((*a)[4])
}

func (a *ARP) SetLinkAddressLength(u uint8) {
	(*a)[4] = u
}

func (a *ARP) GetProtocolAddressLength() uint8 {
	return *&((*a)[5])
}

func (a *ARP) SetProtocolAddressLength(u uint8) {
	(*a)[5] = u
}

func (a *ARP) GetOpCode() uint16 {
	return *(*uint16)(unsafe.Pointer(&((*a)[6])))
}

func (a *ARP) SetOpCode(u uint16) {
	(*a)[6] = (*(*[2]byte)(unsafe.Pointer(&u)))[0]
	(*a)[7] = (*(*[2]byte)(unsafe.Pointer(&u)))[1]
}
