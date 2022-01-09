package bpf

import "github.com/cilium/ebpf"

type Xsk interface {
	GetMapXsk() *ebpf.Map
}

func RegisterXsk(xsk Xsk, queueID int, fd int) error {
	err := xsk.GetMapXsk().Put(uint32(queueID), uint32(fd))
	if err != nil {
		return err
	}

	return nil
}

func UnregisterXsk(xsk Xsk, queueID int) error {
	err := xsk.GetMapXsk().Delete(uint32(queueID))
	if err != nil {
		return err
	}

	return nil
}
