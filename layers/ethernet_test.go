package layers

import (
	"fmt"
	"net"
	"testing"

	"starOcean/utils/binary"
)

func TestEthernet_GetAll(t *testing.T) {
	p := []byte{
		0x94, 0x94, 0x26, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x08, 0x00,
	}

	eth := *(*Ethernet)(&p)
	mac := eth.GetSrcAddress()
	fmt.Println(mac.String())
	mac = eth.GetDstAddress()
	fmt.Println(mac.String())
	typ := eth.GetEthernetType()
	fmt.Println(binary.Swap16(typ))
	fmt.Println(EthernetTypeIPv4)
}

func TestEthernet_SetAll(t *testing.T) {
	p := make([]byte, 14)

	eth := *(*Ethernet)(&p)
	eth.SetSrcAddress(net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06})
	eth.SetDstAddress(net.HardwareAddr{0x06, 0x05, 0x04, 0x03, 0x02, 0x01})
	eth.SetEthernetType(binary.Swap16(uint16(EthernetTypeIPv4)))

	fmt.Printf("%x\n", eth)
}
