package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"

	"starOcean/layers"
	"starOcean/utils/binary"
	"starOcean/utils/checksum"
	"starOcean/xsk"
)

var (
	_localIP  net.IP
	_localMAC net.HardwareAddr
	_fastMode *bool
)

func main() {
	interfaceName := flag.String("interface", "", "interface to bind the eBPF program")
	queueID := flag.Int("qid", -1, "interface queue id")
	localIP := flag.String("ip", "", "interface ip address")
	localMAC := flag.String("mac", "", "interface mac address")
	pprofListen := flag.String("listen", "", "pprof http server address, such as '0.0.0.0:80'")
	_fastMode = flag.Bool("fast", false, "use fast mode")
	flag.Parse()

	var err error

	go http.ListenAndServe(*pprofListen, nil)

	_localIP = net.ParseIP(*localIP).To4()
	if _localIP == nil {
		panic(fmt.Errorf("parse ip failed: %s", *localIP))
	}
	_localMAC, err = net.ParseMAC(*localMAC)
	if err != nil {
		panic(err)
	}

	if runtime.NumCPU() <= 2 {
		runtime.GOMAXPROCS(4)
	}

	if err = rlimit.RemoveMemlock(); err != nil {
		panic(err)
	}

	link, err := netlink.LinkByName(*interfaceName)
	if err != nil {
		panic(err)
	}

	// 添加eBPF程序到网卡
	program, err := xsk.NewProgram()
	if err != nil {
		panic(err)
	}
	if err = program.Attach(link.Attrs().Index); err != nil {
		panic(err)
	}

	// 原本有定期发送FreeARP，但是由于并行可能会产生问题，删除了此部分代码

	socket, err := xsk.NewSocket(link.Attrs().Index, *queueID, &xsk.SocketOptions{
		NumFrame:              4096,
		SizeFrame:             2048,
		NumFillRingDesc:       2048,
		NumCompletionRingDesc: 2048,
		NumRxRingDesc:         2048,
		NumTxRingDesc:         2048,
		UseHugePage:           true,
		HugePage1Gb:           true,
	})
	if err != nil {
		panic(err)
	}

	if err = program.Register(*queueID, socket.FD()); err != nil {
		panic(err)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT)
	go func() {
		<-c
		err := program.Detach(link.Attrs().Index)
		if err != nil {
			panic(errors.Wrap(err, "detach failed"))
		}
		os.Exit(0)
	}()

	for {
		socket.Fill(socket.GetDescs(socket.NumFreeTxSlots()))

		// 删除了PollAdvanced函数，因为还要关注发包队列的消费情况，以便Complete用户态进行消费
		numRx, _, err := socket.Poll(-1)
		if err != nil {
			panic(err)
		}

		rxDescs := socket.Receive(numRx)
		if *_fastMode {
			var txDesc xsk.Desc
			for i, _ := range rxDescs {
				switch getEthernetType(socket, &rxDescs[i]) {
				case layers.EthernetTypeIPv4:
					txDesc = *replyICMPv4(socket, &rxDescs[i])
				case layers.EthernetTypeARP:
					txDesc = *replyARPRequest(socket, &rxDescs[i])
				}
				socket.Transmit([]xsk.Desc{txDesc})
			}
		} else {
			var txDescs []xsk.Desc
			for i, _ := range rxDescs {
				switch getEthernetType(socket, &rxDescs[i]) {
				case layers.EthernetTypeIPv4:
					txDescs = append(txDescs, *replyICMPv4(socket, &rxDescs[i]))
				case layers.EthernetTypeARP:
					txDescs = append(txDescs, *replyARPRequest(socket, &rxDescs[i]))
				}
			}
			socket.Transmit(txDescs)
		}
	}
}

func getEthernetType(socket *xsk.Socket, desc *xsk.Desc) uint16 {
	frame := socket.GetFrame(*desc)
	return binary.Swap16((*(*layers.Ethernet)(&frame)).GetEthernetType())
}

func replyARPRequest(socket *xsk.Socket, rxDesc *xsk.Desc) *xsk.Desc {
	rxFrame := socket.GetFrame(*rxDesc)

	if rxDesc.Len < layers.LengthEthernet+layers.LengthARP+6+4+6+4 {
		return nil
	}

	var txDesc xsk.Desc
	for {
		txDescs := socket.GetDescs(1)
		if len(txDescs) == 1 {
			txDesc = txDescs[0]
			break
		}
	}
	txFrame := socket.GetFrame(txDesc)

	ethReq := *(*layers.Ethernet)(&rxFrame)

	ethResp := *(*layers.Ethernet)(&txFrame)
	ethResp.SetEthernetType(binary.Swap16(layers.EthernetTypeARP))
	ethResp.SetSrcAddress(_localMAC)
	ethResp.SetDstAddress(ethReq.GetSrcAddress())

	arpReqRaw := rxFrame[layers.LengthEthernet:]
	req := *(*layers.ARP)(&arpReqRaw)
	if binary.Swap16(req.GetLinkType()) != layers.LinkTypeEthernet ||
		binary.Swap16(req.GetProtocolType()) != layers.EthernetTypeIPv4 ||
		binary.Swap16(req.GetOpCode()) != layers.ARPRequest ||
		req.GetLinkAddressLength() != 6 ||
		req.GetProtocolAddressLength() != 4 {
		return nil
	}

	arpRespRaw := txFrame[layers.LengthEthernet:]
	resp := *(*layers.ARP)(&arpRespRaw)
	resp.SetLinkType(binary.Swap16(layers.LinkTypeEthernet))
	resp.SetProtocolType(binary.Swap16(layers.EthernetTypeIPv4))
	resp.SetOpCode(binary.Swap16(layers.ARPReply))
	resp.SetLinkAddressLength(6)
	resp.SetProtocolAddressLength(4)
	copy(resp[layers.LengthARP:layers.LengthARP+6], _localMAC[0:6])
	copy(resp[layers.LengthARP+6:layers.LengthARP+10], _localIP[0:4])
	copy(resp[layers.LengthARP+10:layers.LengthARP+16], req[layers.LengthARP:layers.LengthARP+6])
	copy(resp[layers.LengthARP+16:layers.LengthARP+20], req[layers.LengthARP+6:layers.LengthARP+10])

	txDesc.Len = layers.LengthEthernet + layers.LengthARP + 6 + 4 + 6 + 4
	return &txDesc
}

func genGratuitousARP(socket *xsk.Socket, desc *xsk.Desc) {
	frame := socket.GetFrame(*desc)

	eth := *(*layers.Ethernet)(&frame)
	eth.SetSrcAddress(_localMAC)
	eth.SetDstAddress([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	eth.SetEthernetType(binary.Swap16(layers.EthernetTypeARP))

	t := frame[layers.LengthEthernet:]
	arp := *(*layers.ARP)(&t)
	arp.SetLinkType(binary.Swap16(layers.LinkTypeEthernet))
	arp.SetProtocolType(binary.Swap16(layers.EthernetTypeIPv4))
	arp.SetLinkAddressLength(6)
	arp.SetProtocolAddressLength(4)
	arp.SetOpCode(binary.Swap16(layers.ARPReply))

	index := layers.LengthARP
	// copy sender mac
	copy(t[index:index+6], _localMAC[:6])
	index += 6
	// copy sender ip
	copy(t[index:index+4], _localIP[:4])
	index += 4
	// set broadcast mac
	t[index] = 0xff
	t[index+1] = 0xff
	t[index+2] = 0xff
	t[index+3] = 0xff
	t[index+4] = 0xff
	t[index+5] = 0xff
	index += 6
	// copy target ip
	copy(t[index:index+4], _localIP[:4])
	index += 4

	desc.Len = uint32(layers.LengthEthernet + index)
}

func replyICMPv4(socket *xsk.Socket, rxDesc *xsk.Desc) *xsk.Desc {
	rxFrame := socket.GetFrame(*rxDesc)

	eth := *(*layers.Ethernet)(&rxFrame)
	tmpMac := make([]byte, 6)
	copy(tmpMac, eth.GetSrcAddress()[0:6])
	eth.SetSrcAddress(eth.GetDstAddress())
	eth.SetDstAddress(tmpMac)

	ipRaw := rxFrame[layers.LengthEthernet:]
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

	icmpRaw := rxFrame[layers.LengthEthernet+layers.LengthIPv4Min:]
	icmp := *(*layers.ICMPv4)(&icmpRaw)
	icmp.SetType(layers.ICMPv4TypeEchoReply)
	icmp.SetChecksum(0)
	icmp.SetChecksum(binary.Swap16(checksum.TCPIPChecksum(icmpRaw, 0)))

	return rxDesc
}
