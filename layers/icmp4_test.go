package layers

import (
	"fmt"
	"testing"

	"starOcean/utils/binary"
	"starOcean/utils/checksum"
)

func TestICMPv4_GetAll(t *testing.T) {
	p := []byte{
		0x08, 0x00, 0x8f, 0x3e, 0x04, 0x04, 0x00, 0x01,
	}

	icmp4 := *(*ICMPv4)(&p)
	fmt.Println(icmp4.GetType())
	fmt.Println(icmp4.GetCode())
	fmt.Println(binary.Swap16(icmp4.GetChecksum()))
	fmt.Println(binary.Swap16(icmp4.GetID()))
	fmt.Println(binary.Swap16(icmp4.GetSequence()))
}

func TestICMPv4_SetAll(t *testing.T) {
	p := make([]byte, 8)
	icmp4 := *(*ICMPv4)(&p)
	icmp4.SetType(ICMPv4TypeEchoRequest)
	icmp4.SetCode(ICMPv4CodeNet)
	icmp4.SetChecksum(0)
	icmp4.SetID(binary.Swap16(1))
	icmp4.SetSequence(binary.Swap16(1))

	icmp4.SetChecksum(binary.Swap16(checksum.TCPIPChecksum(p, 0)))

	fmt.Printf("%x\n", p)
}
