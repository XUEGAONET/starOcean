package raw

import (
	"net"
	"syscall"

	"github.com/pkg/errors"

	"starOcean/utils/binary"
)

const (
	_buffLen = 9000
)

var (
	ErrBufferIsFull = errors.New("buffer is full")
)

type Raw struct {
	fd        int
	buf       []byte
	filter    func([]byte) bool // return true to pass, or false to drop
	linkLayer syscall.SockaddrLinklayer
}

func New(interfaceName string, protocol int, filter func([]byte) bool, gw net.HardwareAddr) (*Raw, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(binary.Htons16(uint16(protocol))))
	if err != nil {
		return nil, errors.WithStack(err)
	}

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if err = syscall.BindToDevice(fd, interfaceName); err != nil {
		return nil, errors.WithStack(err)
	}

	if err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		return nil, errors.WithStack(err)
	}

	var l2DstAddr [8]byte
	copy(l2DstAddr[:], iface.HardwareAddr[:])
	return &Raw{
		fd:     fd,
		buf:    make([]byte, _buffLen),
		filter: filter,
		linkLayer: syscall.SockaddrLinklayer{
			Protocol: binary.Htons16(uint16(protocol)),
			Ifindex:  iface.Index,
			Hatype:   0,
			Pkttype:  0,
			Halen:    6,
			Addr:     l2DstAddr,
		},
	}, nil
}

func (r *Raw) Read(buf []byte) (int, error) {
	for {
		n, _, err := syscall.Recvfrom(r.fd, r.buf, 0)
		if err != nil {
			return 0, errors.WithStack(err)
		}

		if r.filter != nil {
			if !r.filter(r.buf[:n]) {
				continue
			}
		}

		if n > len(buf) {
			return 0, errors.WithStack(ErrBufferIsFull)
		}

		copy(buf, r.buf[:n])
		return n, nil
	}
}

func (r *Raw) Write(buf []byte) (int, error) {
	return len(buf), syscall.Sendto(r.fd, buf, 0, &r.linkLayer)
}
