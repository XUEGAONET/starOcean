package xsk

import (
	"os"
	"os/signal"
	"syscall"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestNewAll(t *testing.T) {
	const LinkName = "ens19"
	const QueueID = 0

	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}

	link, err := netlink.LinkByName(LinkName)
	if err != nil {
		panic(err)
	}

	program, err := NewProgram()
	if err != nil {
		panic(err)
	}
	if err := program.Attach(link.Attrs().Index); err != nil {
		panic(err)
	}

	DefaultSocketFlags = unix.XDP_COPY
	DefaultXdpFlags = unix.XDP_FLAGS_HW_MODE
	xsk, err := NewSocket(link.Attrs().Index, QueueID, nil)
	if err != nil {
		panic(err)
	}

	if err := program.Register(QueueID, xsk.FD()); err != nil {
		panic(err)
	}

	// Remove the XDP BPF program on interrupt.
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		program.Detach(link.Attrs().Index)
		os.Exit(1)
	}()

	for {
		xsk.Fill(xsk.GetDescs(xsk.NumFreeFillSlots()))
		numRx, _, err := xsk.Poll(-1)
		if err != nil {
			panic(err)
		}
		rxDescs := xsk.Receive(numRx)
		for i := 0; i < len(rxDescs); i++ {
			// Set destination MAC address to
			// ff:ff:ff:ff:ff:ff
			frame := xsk.GetFrame(rxDescs[i])
			for i := 0; i < 6; i++ {
				frame[i] = byte(0xff)
			}
		}
		xsk.Transmit(rxDescs)
	}
}
