package layers

import "unsafe"

//struct tcphdr {
//	__be16	source;
//	__be16	dest;
//	__be32	seq;
//	__be32	ack_seq;
//#if defined(__LITTLE_ENDIAN_BITFIELD)
//	__u16	res1:4,
//		doff:4,
//		fin:1,
//		syn:1,
//		rst:1,
//		psh:1,
//		ack:1,
//		urg:1,
//		ece:1,
//		cwr:1;
//#elif defined(__BIG_ENDIAN_BITFIELD)
//	__u16	doff:4,
//		res1:4,
//		cwr:1,
//		ece:1,
//		urg:1,
//		ack:1,
//		psh:1,
//		rst:1,
//		syn:1,
//		fin:1;
//#else
//#error	"Adjust your <asm/byteorder.h> defines"
//#endif
//	__be16	window;
//	__sum16	check;
//	__be16	urg_ptr;
//};

type TCP []byte

const (
	LengthTCPMin = 20
	LengthTCPMax = 60
)

func (t *TCP) GetSrcPort() uint16 {
	return *(*uint16)(unsafe.Pointer(&(*t)[0]))
}

func (t *TCP) SetSrcPort(p uint16) {
	(*t)[0] = (*(*[2]byte)(unsafe.Pointer(&p)))[0]
	(*t)[1] = (*(*[2]byte)(unsafe.Pointer(&p)))[1]
}

func (t *TCP) GetDstPort() uint16 {
	return *(*uint16)(unsafe.Pointer(&(*t)[2]))
}

func (t *TCP) SetDstPort(p uint16) {
	(*t)[2] = (*(*[2]byte)(unsafe.Pointer(&p)))[0]
	(*t)[3] = (*(*[2]byte)(unsafe.Pointer(&p)))[1]
}

func (t *TCP) GetSeq() uint32 {
	return *(*uint32)(unsafe.Pointer(&(*t)[4]))
}

func (t *TCP) SetSeq(seq uint32) {
	(*t)[4] = (*(*[4]byte)(unsafe.Pointer(&seq)))[0]
	(*t)[5] = (*(*[4]byte)(unsafe.Pointer(&seq)))[1]
	(*t)[6] = (*(*[4]byte)(unsafe.Pointer(&seq)))[2]
	(*t)[7] = (*(*[4]byte)(unsafe.Pointer(&seq)))[3]
}

func (t *TCP) GetAckSeq() uint32 {
	return *(*uint32)(unsafe.Pointer(&(*t)[8]))
}

func (t *TCP) SetAckSeq(seq uint32) {
	(*t)[8] = (*(*[4]byte)(unsafe.Pointer(&seq)))[0]
	(*t)[9] = (*(*[4]byte)(unsafe.Pointer(&seq)))[1]
	(*t)[10] = (*(*[4]byte)(unsafe.Pointer(&seq)))[2]
	(*t)[11] = (*(*[4]byte)(unsafe.Pointer(&seq)))[3]
}

func (t *TCP) GetDataOffset() uint8 {
	return ((*t)[12] >> 4) * 4
}

func (t *TCP) SetDataOffset(i uint8) {
	(*t)[12] |= (i / 4) << 4
}

func (t *TCP) GetReserved() uint8 {
	return (*t)[12] << 4 >> 5
}

func (t *TCP) SetReserved(i uint8) {
	(*t)[12] |= i << 4 >> 5 << 1
}

func (t *TCP) IsFlagCWR() bool {
	return (*t)[13]&128 == 128
}

func (t *TCP) SetFlagCWR(b bool) {
	if b {
		(*t)[13] |= 128
	}
}

func (t *TCP) IsFlagECE() bool {
	return (*t)[13]&64 == 64
}

func (t *TCP) SetFlagECE(b bool) {
	if b {
		(*t)[13] |= 64
	}
}

func (t *TCP) IsFlagUrg() bool {
	return (*t)[13]&32 == 32
}

func (t *TCP) SetFlagUrg(b bool) {
	if b {
		(*t)[13] |= 32
	}
}

func (t *TCP) IsFlagAck() bool {
	return (*t)[13]&16 == 16
}

func (t *TCP) SetFlagAck(b bool) {
	if b {
		(*t)[13] |= 16
	}
}

func (t *TCP) IsFlagPsh() bool {
	return (*t)[13]&8 == 8
}

func (t *TCP) SetFlagPsh(b bool) {
	if b {
		(*t)[13] |= 8
	}
}

func (t *TCP) IsFlagRst() bool {
	return (*t)[13]&4 == 4
}

func (t *TCP) SetFlagRst(b bool) {
	if b {
		(*t)[13] |= 4
	}
}

func (t *TCP) IsFlagSyn() bool {
	return (*t)[13]&2 == 2
}

func (t *TCP) SetFlagSyn(b bool) {
	if b {
		(*t)[13] |= 2
	}
}

func (t *TCP) IsFlagFin() bool {
	return (*t)[13]&1 == 1
}

func (t *TCP) SetFlagFin(b bool) {
	if b {
		(*t)[13] |= 1
	}
}

func (t *TCP) GetWindow() uint16 {
	return *(*uint16)(unsafe.Pointer(&(*t)[14]))
}

func (t *TCP) SetWindow(w uint16) {
	(*t)[14] = (*(*[2]byte)(unsafe.Pointer(&w)))[0]
	(*t)[15] = (*(*[2]byte)(unsafe.Pointer(&w)))[1]
}

func (t *TCP) GetChecksum() uint16 {
	return *(*uint16)(unsafe.Pointer(&(*t)[16]))
}

func (t *TCP) SetChecksum(c uint16) {
	(*t)[16] = (*(*[2]byte)(unsafe.Pointer(&c)))[0]
	(*t)[17] = (*(*[2]byte)(unsafe.Pointer(&c)))[1]
}

func (t *TCP) GetUrgPointer() uint16 {
	return *(*uint16)(unsafe.Pointer(&(*t)[18]))
}

func (t *TCP) SetUrgPointer(w uint16) {
	(*t)[18] = (*(*[2]byte)(unsafe.Pointer(&w)))[0]
	(*t)[19] = (*(*[2]byte)(unsafe.Pointer(&w)))[1]
}
