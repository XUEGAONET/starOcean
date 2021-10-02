package raw

import (
	"fmt"
	"net"
	"syscall"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestRaw_Write(t *testing.T) {
	fd, err := New("ens18", syscall.ETH_P_IP, nil, net.HardwareAddr{0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE})
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

		//err = fd.Write(gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.NoCopy))
		//if err != nil {
		//	panic(err)
		//}

		p := gopacket.NewPacket(buf[:n], layers.LayerTypeEthernet, gopacket.NoCopy)
		fmt.Printf("%+v\n\n", p)

		wbuf := []byte{
			238, 238, 238, 238, 238, 238,
			206, 155, 84, 81, 82, 81,
			8, 0, 69, 0, 0, 60, 108, 63, 0, 0, 124, 1, 174, 43, 100, 97, 73, 214, 100, 99, 17, 188,
			8, 0, 61, 206, 0, 1, 15, 141, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108,
			109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 97, 98, 99, 100, 101, 102, 103, 104, 105,
		}

		wbuf[len(wbuf)]

		n, err = fd.Write(wbuf)
		if err != nil {
			panic(err)
		}
	}
}
