package layers

import (
	"net"
	"unsafe"
)

const (
	IPProtocolIPv6HopByHop    uint8 = 0
	IPProtocolICMPv4          uint8 = 1
	IPProtocolIGMP            uint8 = 2
	IPProtocolIPv4            uint8 = 4
	IPProtocolTCP             uint8 = 6
	IPProtocolUDP             uint8 = 17
	IPProtocolRUDP            uint8 = 27
	IPProtocolIPv6            uint8 = 41
	IPProtocolIPv6Routing     uint8 = 43
	IPProtocolIPv6Fragment    uint8 = 44
	IPProtocolGRE             uint8 = 47
	IPProtocolESP             uint8 = 50
	IPProtocolAH              uint8 = 51
	IPProtocolICMPv6          uint8 = 58
	IPProtocolNoNextHeader    uint8 = 59
	IPProtocolIPv6Destination uint8 = 60
	IPProtocolOSPF            uint8 = 89
	IPProtocolIPIP            uint8 = 94
	IPProtocolEtherIP         uint8 = 97
	IPProtocolVRRP            uint8 = 112
	IPProtocolSCTP            uint8 = 132
	IPProtocolUDPLite         uint8 = 136
	IPProtocolMPLSInIP        uint8 = 137
)

// IPv4 is the header of an IP packet.
//  struct iphdr {
//  #if defined(__LITTLE_ENDIAN_BITFIELD)
//  	__u8	ihl:4,
//  		version:4;
//  #elif defined (__BIG_ENDIAN_BITFIELD)
//  	__u8	version:4,
//    		ihl:4;
//  #else
//  #error	"Please fix <asm/byteorder.h>"
//  #endif
//  	__u8	tos;
//  	__be16	tot_len;
//  	__be16	id;
//  	__be16	frag_off;
//  	__u8	ttl;
//  	__u8	protocol;
//  	__sum16	check;
//  	__be32	saddr;
//  	__be32	daddr;
//  	/*The options start here. */
//  };
type IPv4 []byte

const (
	LengthIPv4Min = 20
	LengthIPv4Max = 60
)

func (p *IPv4) GetVersion() uint8 {
	return (*p)[0] >> 4
}

func (p *IPv4) SetVersion(i uint8) {
	(*p)[0] |= i << 4
}

func (p *IPv4) GetIHL() uint8 {
	return ((*p)[0] << 4 >> 4) * 4
}

func (p *IPv4) SetIHL(i uint8) {
	(*p)[0] |= (i / 4) << 4 >> 4
}

func (p *IPv4) GetTOS() uint8 {
	return *&(*p)[1]
}

func (p *IPv4) SetTOS(i uint8) {
	(*p)[1] = i
}

func (p *IPv4) GetTotalLen() uint16 {
	return *(*uint16)(unsafe.Pointer(&(*p)[2]))
}

func (p *IPv4) SetTotalLen(i uint16) {
	(*p)[2] = (*(*[2]byte)(unsafe.Pointer(&i)))[0]
	(*p)[3] = (*(*[2]byte)(unsafe.Pointer(&i)))[1]
}

func (p *IPv4) GetID() uint16 {
	return *(*uint16)(unsafe.Pointer(&(*p)[4]))
}

func (p *IPv4) SetID(i uint16) {
	(*p)[4] = (*(*[2]byte)(unsafe.Pointer(&i)))[0]
	(*p)[5] = (*(*[2]byte)(unsafe.Pointer(&i)))[1]
}

func (p *IPv4) GetFragOff() uint16 {
	t := (*p)[6:8]
	return (*(*uint16)(unsafe.Pointer(&t[0]))) << 3 >> 3
}

func (p *IPv4) SetFragOff(i uint16) {
	(*p)[6] |= (*(*[2]byte)(unsafe.Pointer(&i)))[0] << 3 >> 3
	(*p)[7] = (*(*[2]byte)(unsafe.Pointer(&i)))[1]
}

func (p *IPv4) GetTTL() uint8 {
	return *&(*p)[8]
}

func (p *IPv4) SetTTL(i uint8) {
	(*p)[8] = i
}

func (p *IPv4) GetProtocol() uint8 {
	return *&(*p)[9]
}

func (p *IPv4) SetProtocol(i uint8) {
	(*p)[9] = i
}

func (p *IPv4) GetChecksum() uint16 {
	return *(*uint16)(unsafe.Pointer(&(*p)[10]))
}

func (p *IPv4) SetChecksum(i uint16) {
	(*p)[10] = (*(*[2]byte)(unsafe.Pointer(&i)))[0]
	(*p)[11] = (*(*[2]byte)(unsafe.Pointer(&i)))[1]
}

func (p *IPv4) GetSrcAddr() net.IP {
	t := (*p)[12:16]
	return *(*net.IP)(&t)
}

func (p *IPv4) SetSrcAddr(i net.IP) {
	copy((*p)[12:16], i[0:4])
}

func (p *IPv4) GetDstAddr() net.IP {
	t := (*p)[16:20]
	return *(*net.IP)(&t)
}

func (p *IPv4) SetDstAddr(i net.IP) {
	copy((*p)[16:20], i[0:4])
}

func (p *IPv4) IsFlagReserved() bool {
	return (*p)[6]&128 == 128
}

func (p *IPv4) SetFlagReserved(b bool) {
	if b {
		(*p)[6] |= 128
	}
}

func (p *IPv4) IsFlagDontFrag() bool {
	return (*p)[6]&64 == 64
}

func (p *IPv4) SetFlagDontFrag(b bool) {
	if b {
		(*p)[6] |= 64
	}
}

func (p *IPv4) IsFlagMoreFrag() bool {
	return (*p)[6]&32 == 32
}

func (p *IPv4) SetFlagMoreFrag(b bool) {
	if b {
		(*p)[6] |= 32
	}
}
