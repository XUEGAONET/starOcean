package xdp

import (
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

type Config struct {
	UMemChunkNum          int
	UMemChunkSize         int
	FillRingDescNum       int
	CompletionRingDescNum int
	RxRingDescNum         int
	TxRingDescNum         int
}

type Socket struct {
	fd   int
	umem []byte
}

func New(config *Config) (*Socket, error) {
	var socket Socket
	var err error

	socket.fd, err = syscall.Socket(unix.AF_XDP, syscall.SOCK_RAW, 0)
	if err != nil {
		return nil, errors.WithMessage(err, "create xdp socket failed")
	}

	socket.umem, err = syscall.Mmap(-1, 0, config.UMemChunkNum*config.UMemChunkSize,
		// readable and writable
		syscall.PROT_READ|syscall.PROT_WRITE,
		// new memory block, and not use file descriptor, and preset all pages to zero
		syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS|syscall.MAP_POPULATE)
	if err != nil {
		socket.Close()
		return nil, errors.WithMessage(err, "create userspace shared memory failed")
	}

	xdpUMemReg := unix.XDPUmemReg{
		Addr:     uint64(uintptr(unsafe.Pointer(&socket.umem[0]))),
		Len:      uint64(len(socket.umem)),
		Size:     uint32(config.UMemChunkSize),
		Headroom: 0,
		Flags:    0,
	}

	var errno syscall.Errno
	var rc uintptr

	rc, _, errno = unix.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(socket.fd),
		unix.SOL_XDP, unix.XDP_UMEM_REG,
		uintptr(unsafe.Pointer(&xdpUMemReg)),
		unsafe.Sizeof(xdpUMemReg), 0)
	if rc != 0 {
		socket.Close()
		return nil, errors.WithMessage(errno, "setsockopt XDP_UMEM_REG failed")
	}

	err = syscall.SetsockoptInt(socket.fd, unix.SOL_XDP, unix.XDP_UMEM_FILL_RING, config.FillRingDescNum)
	if err != nil {
		socket.Close()
		return nil, errors.WithMessage(err, "setsockopt XDP_UMEM_FILL_RING failed")
	}

	err = unix.SetsockoptInt(socket.fd, unix.SOL_XDP, unix.XDP_UMEM_COMPLETION_RING, config.CompletionRingDescNum)
	if err != nil {
		socket.Close()
		return nil, errors.WithMessage(err, "setsockopt XDP_UMEM_COMPLETION_RING failed")
	}

	err = unix.SetsockoptInt(socket.fd, unix.SOL_XDP, unix.XDP_RX_RING, config.RxRingDescNum)
	if err != nil {
		socket.Close()
		return nil, errors.WithMessage(err, "setsockopt XDP_RX_RING failed")
	}

	err = unix.SetsockoptInt(socket.fd, unix.SOL_XDP, unix.XDP_TX_RING, config.TxRingDescNum)
	if err != nil {
		socket.Close()
		return nil, errors.WithMessage(err, "setsockopt XDP_TX_RING failed")
	}

	var xdpMMapOffsets unix.XDPMmapOffsets
	xdpMMapOffsetsLen := uint32(unsafe.Sizeof(xdpMMapOffsets))
	rc, _, errno = unix.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(socket.fd),
		unix.SOL_XDP, unix.XDP_MMAP_OFFSETS,
		uintptr(unsafe.Pointer(&xdpMMapOffsets)),
		uintptr(unsafe.Pointer(&xdpMMapOffsetsLen)), 0)
	if rc != 0 {
		socket.Close()
		return nil, errors.WithMessage(errno, "getsockopt XDP_MMAP_OFFSETS failed")
	}

	return nil, nil
}

func (s Socket) Close() {
	_ = syscall.Close(s.fd)
	_ = syscall.Munmap(s.umem)
	s.umem = nil

}
