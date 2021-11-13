package xsk

import (
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

type umemRing struct {
	Producer *uint32
	Consumer *uint32
	Descs    []uint64
}

type rxTxRing struct {
	Producer *uint32
	Consumer *uint32
	Descs    []Desc
}

// A Socket is an implementation of the AF_XDP Linux socket type for reading packets from a device.
type Socket struct {
	fd int

	// umem 会被分为两部分空间，前一半用于接收，后一半用于发送
	umem []byte
	// only store addr in []uint64
	fillRing       umemRing
	completionRing umemRing
	// only store Desc in []Desc
	rxRing rxTxRing
	txRing rxTxRing

	rxDescs       []Desc
	txDescs       []Desc
	fillDescs     []Desc
	completeDescs []Desc

	xsksMap *ebpf.Map
	program *ebpf.Program
	ifindex int
	options SocketOptions

	countCompleted   uint64
	countFilled      uint64
	countReceived    uint64
	countTransmitted uint64

	numFillRingDescMask       uint32
	numCompletionRingDescMask uint32
	numRxRingDescMask         uint32
	numTxRingDescMask         uint32
}

// SocketOptions are configuration settings used to bind an XDP socket.
type SocketOptions struct {
	NumFrame              int
	SizeFrame             int
	NumFillRingDesc       int
	NumCompletionRingDesc int
	NumRxRingDesc         int
	NumTxRingDesc         int

	UseHugePage bool
	HugePage1Gb bool
}

// Desc represents an XDP Rx/Tx descriptor.
type Desc unix.XDPDesc

// Stats contains various counters of the XDP socket, such as numbers of
// sent/received frames.
type Stats struct {
	Filled      uint64
	Completed   uint64
	Received    uint64
	Transmitted uint64
	KernelStats unix.XDPStatistics
}
