package xsk

import (
	"log"
	//_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"starOcean/layers"
	"starOcean/utils/binary"
	"starOcean/utils/checksum"
)

func TestSendICMPv4(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	//go http.ListenAndServe("0.0.0.0:6060", nil)

	const (
		//InterfaceName = "ens1f1"
		InterfaceName = "ens19"
		QueueID       = 0
	)

	link, err := netlink.LinkByName(InterfaceName)
	if err != nil {
		t.Fatal(err)
	}

	program, err := NewProgram()
	if err != nil {
		t.Fatal(err)
	}

	if err := program.Attach(link.Attrs().Index); err != nil {
		t.Fatal(err)
	}

	xsk, err := NewSocket(link.Attrs().Index, QueueID, nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := program.Register(QueueID, xsk.FD()); err != nil {
		t.Fatal(err)
	}

	// Remove the XDP BPF program on interrupt.
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		program.Detach(link.Attrs().Index)
		t.Fatal(err)
	}()

	for {
		xsk.Fill(xsk.GetDescs(xsk.NumFreeTxSlots()))
		numRx, _, err := xsk.PollAdvanced(-1, unix.POLLIN)
		if err != nil {
			t.Fatal(err)
		}

		rxDescs := xsk.Receive(numRx)

		for i, _ := range rxDescs {
			rxFrame := xsk.GetFrame(rxDescs[i])
			replyICMPv4(rxFrame)
		}

		xsk.Transmit(rxDescs)
	}
}

func replyICMPv4(pkt []byte) {
	eth := *(*layers.Ethernet)(&pkt)
	tmpMac := make([]byte, 6)
	copy(tmpMac, eth.GetSrcAddress()[0:6])
	eth.SetSrcAddress(eth.GetDstAddress())
	eth.SetDstAddress(tmpMac)

	ipRaw := pkt[14:]
	ipv4 := *(*layers.IPv4)(&ipRaw)
	tmpIP := make([]byte, 4)
	copy(tmpIP, ipv4.GetSrcAddr())
	ipv4.SetSrcAddr(ipv4.GetDstAddr())
	ipv4.SetDstAddr(tmpIP)
	ipv4.SetTTL(32)
	ipv4.SetFragOff(0)
	ipv4.SetFlagDontFrag(true)
	ipv4.SetChecksum(0)
	ipv4.SetChecksum(binary.Swap16(checksum.TCPIPChecksum(ipv4[:ipv4.GetIHL()], 0)))

	icmpRaw := pkt[34:]
	icmp := *(*layers.ICMPv4)(&icmpRaw)
	icmp.SetType(layers.ICMPv4TypeEchoReply)
	icmp.SetChecksum(0)
	icmp.SetChecksum(binary.Swap16(checksum.TCPIPChecksum(icmpRaw, 0)))
}
