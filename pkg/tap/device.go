package tap

import (
	"os"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
)

func NewPtr(name string) (uintptr, error) {
	fd, err := createFd()
	if err != nil {
		return 0, err
	}

	err = openDev(fd, name)
	if err != nil {
		return 0, errors.Wrap(err, "open tap failed")
	}

	return fd, nil
}

func NewFile(name string) (*os.File, error) {
	fd, err := NewPtr(name)
	if err != nil {
		return nil, err
	}

	return os.NewFile(fd, "tap"), nil
}

func createFd() (uintptr, error) {
	res, err := syscall.Open("/dev/net/tun", os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		return 0, errors.Wrap(err, "open /dev/net/tun failed")
	}

	return uintptr(res), nil
}

func openDev(fd uintptr, name string) error {
	var r req

	copy(r.Name[:], name)
	r.Flags = syscall.IFF_TAP | syscall.IFF_NO_PI
	err := ioctl(fd, syscall.TUNSETIFF, uintptr(unsafe.Pointer(&r)))
	if err != nil {
		return errors.Wrap(err, "ioctl set IFF_TAP and IFF_NO_PI failed")
	}

	return nil
}
