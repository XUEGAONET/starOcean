package layers

import (
	"unsafe"
)

// struct udphdr {
//	__be16	source;
//	__be16	dest;
//	__be16	len;
//	__sum16	check;
// };

type UDP []byte

const LengthUDP = 8

func (u *UDP) GetSrcPort() uint16 {
	return *(*uint16)(unsafe.Pointer(&(*u)[0]))
}

func (u *UDP) SetSrcPort(p uint16) {
	(*u)[0] = (*(*[2]byte)(unsafe.Pointer(&p)))[0]
	(*u)[1] = (*(*[2]byte)(unsafe.Pointer(&p)))[1]
}

func (u *UDP) GetDstPort() uint16 {
	return *(*uint16)(unsafe.Pointer(&(*u)[2]))
}

func (u *UDP) SetDstPort(p uint16) {
	(*u)[2] = (*(*[2]byte)(unsafe.Pointer(&p)))[0]
	(*u)[3] = (*(*[2]byte)(unsafe.Pointer(&p)))[1]
}

func (u *UDP) GetLen() uint16 {
	return *(*uint16)(unsafe.Pointer(&(*u)[4]))
}

func (u *UDP) SetLen(l uint16) {
	(*u)[4] = (*(*[2]byte)(unsafe.Pointer(&l)))[0]
	(*u)[5] = (*(*[2]byte)(unsafe.Pointer(&l)))[1]
}

func (u *UDP) GetChecksum() uint16 {
	return *(*uint16)(unsafe.Pointer(&(*u)[6]))
}

func (u *UDP) SetChecksum(l uint16) {
	(*u)[6] = (*(*[2]byte)(unsafe.Pointer(&l)))[0]
	(*u)[7] = (*(*[2]byte)(unsafe.Pointer(&l)))[1]
}
