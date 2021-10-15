package xsk

import (
	"fmt"
	"log"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/asavie/xdp"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func forwardL2(verbose bool, inLink netlink.Link, inLinkQueueID int, inLinkDst net.HardwareAddr, outLink netlink.Link, outLinkQueueID int, outLinkDst net.HardwareAddr) {
	log.Printf("attaching XDP program for %s...", inLink.Attrs().Name)

	inProg, err := xdp.NewProgram(inLinkQueueID + 1)
	if err != nil {
		log.Fatalf("failed to create xdp program: %v\n", err)
	}

	if err := inProg.Attach(inLink.Attrs().Index); err != nil {
		log.Fatalf("failed to attach xdp program to interface: %v\n", err)
	}
	defer inProg.Detach(inLink.Attrs().Index)

	log.Printf("opening XDP socket for %s...", inLink.Attrs().Name)

	inXsk, err := xdp.NewSocket(inLink.Attrs().Index, inLinkQueueID, nil)
	if err != nil {
		log.Fatalf("failed to open XDP socket for link %s: %v", inLink.Attrs().Name, err)
	}

	log.Printf("registering XDP socket for %s...", inLink.Attrs().Name)

	if err := inProg.Register(inLinkQueueID, inXsk.FD()); err != nil {
		fmt.Printf("error: failed to register socket in BPF map: %v\n", err)
		return
	}
	defer inProg.Unregister(inLinkQueueID)

	// Note: The XDP socket used for transmitting data does not need an EBPF program.
	log.Printf("opening XDP socket for %s...", outLink.Attrs().Name)

	outXsk, err := xdp.NewSocket(outLink.Attrs().Index, outLinkQueueID, nil)
	if err != nil {
		log.Fatalf("failed to open XDP socket for link %s: %v", outLink.Attrs().Name, err)
	}

	log.Printf("starting L2 forwarder...")

	numBytesTotal := uint64(0)
	numFramesTotal := uint64(0)
	if verbose {
		go func() {
			var numBytesPrev, numFramesPrev uint64
			var numBytesNow, numFramesNow uint64
			for {
				numBytesPrev = numBytesNow
				numFramesPrev = numFramesNow
				time.Sleep(time.Duration(1) * time.Second)
				numBytesNow = numBytesTotal
				numFramesNow = numFramesTotal
				pps := numFramesNow - numFramesPrev
				bps := (numBytesNow - numBytesPrev) * 8
				log.Printf("%9d pps / %6d Mbps", pps, bps/1000000)
			}
		}()
	}

	var fds [2]unix.PollFd
	fds[0].Fd = int32(inXsk.FD())
	fds[1].Fd = int32(outXsk.FD())
	for {
		inXsk.Fill(inXsk.GetDescs(inXsk.NumFreeFillSlots()))
		outXsk.Fill(outXsk.GetDescs(outXsk.NumFreeFillSlots()))

		fds[0].Events = unix.POLLIN
		if inXsk.NumTransmitted() > 0 {
			fds[0].Events |= unix.POLLOUT
		}

		fds[1].Events = unix.POLLIN
		if outXsk.NumTransmitted() > 0 {
			fds[1].Events |= unix.POLLOUT
		}

		fds[0].Revents = 0
		fds[1].Revents = 0
		_, err := unix.Poll(fds[:], -1)
		if err == syscall.EINTR {
			// EINTR is a non-fatal error that may occur due to ongoing syscalls that interrupt our poll
			continue
		} else if err != nil {
			fmt.Fprintf(os.Stderr, "poll failed: %v\n", err)
			os.Exit(1)
		}

		if (fds[0].Revents & unix.POLLIN) != 0 {
			numBytes, numFrames := forwardFrames(inXsk, outXsk, inLinkDst)
			numBytesTotal += numBytes
			numFramesTotal += numFrames
		}
		if (fds[0].Revents & unix.POLLOUT) != 0 {
			inXsk.Complete(inXsk.NumCompleted())
		}
		if (fds[1].Revents & unix.POLLIN) != 0 {
			numBytes, numFrames := forwardFrames(outXsk, inXsk, outLinkDst)
			numBytesTotal += numBytes
			numFramesTotal += numFrames
		}
		if (fds[1].Revents & unix.POLLOUT) != 0 {
			outXsk.Complete(outXsk.NumCompleted())
		}
	}
}

func forwardFrames(input *xdp.Socket, output *xdp.Socket, dstMac net.HardwareAddr) (numBytes uint64, numFrames uint64) {
	inDescs := input.Receive(input.NumReceived())
	replaceDstMac(input, inDescs, dstMac)

	outDescs := output.GetDescs(output.NumFreeTxSlots())

	if len(inDescs) > len(outDescs) {
		inDescs = inDescs[:len(outDescs)]
	}
	numFrames = uint64(len(inDescs))

	for i := 0; i < len(inDescs); i++ {
		outFrame := output.GetFrame(outDescs[i])
		inFrame := input.GetFrame(inDescs[i])
		numBytes += uint64(len(inFrame))
		outDescs[i].Len = uint32(copy(outFrame, inFrame))
	}
	outDescs = outDescs[:len(inDescs)]

	output.Transmit(outDescs)

	return
}

func replaceDstMac(xsk *xdp.Socket, descs []xdp.Desc, dstMac net.HardwareAddr) {
	for _, d := range descs {
		frame := xsk.GetFrame(d)
		copy(frame, dstMac)
	}
}
