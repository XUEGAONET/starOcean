package raw

import (
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestRaw_Write(t *testing.T) {
	fd, err := New("eth0", syscall.ETH_P_IP, nil, net.HardwareAddr{0xfe, 0xee, 0x8f, 0xbf, 0x86, 0x99})
	if err != nil {
		panic(err)
	}

	buf := make([]byte, 10240)
	for {
		n, err := fd.Read(buf)
		if err != nil {
			panic(err)
		}

		fmt.Printf("%+v\n", buf[:n])

		time.Sleep(time.Second)

		buf := gopacket.NewSerializeBuffer()
		eth := layers.Ethernet{
			SrcMAC:       []byte{0x52, 0x54, 0x00, 0x0a, 0xbc, 0x94},
			DstMAC:       []byte{0xfe, 0xee, 0x8f, 0xbf, 0x86, 0x99},
			EthernetType: layers.EthernetTypeIPv4,
		}
		ipv4 := layers.IPv4{
			Version:    4,
			IHL:        0,
			TOS:        22,
			Length:     0,
			Id:         0,
			Flags:      0,
			FragOffset: 0,
			TTL:        122,
			Protocol:   layers.IPProtocolICMPv4,
			Checksum:   0,
			SrcIP:      []byte{10, 0, 4, 14},
			DstIP:      []byte{223, 5, 5, 5},
			Options:    []layers.IPv4Option{},
			Padding:    []byte{},
		}
		icmpv4 := layers.ICMPv4{
			TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, layers.ICMPv4CodeNet),
			Checksum: 0,
			Id:       22,
			Seq:      33,
		}
		err = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}, &eth, &ipv4, &icmpv4)
		if err != nil {
			t.Fatal(err)
		}

		n, err = fd.Write(buf.Bytes())
		if err != nil {
			panic(err)
		}
	}
}
