package xsk

import (
	"log"
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestXdp(t *testing.T) {
	var inLinkName string = "ens19"
	var inLinkDstStr string = "94:94:a6:00:01:88"
	var inLinkQueueID int = 0
	var outLinkName string = "ens19"
	var outLinkDstStr string = "94:94:a6:00:01:89"
	var outLinkQueueID int = 1

	inLinkDst, err := net.ParseMAC(inLinkDstStr)
	if err != nil {
		t.Fatal(err)
	}

	outLinkDst, err := net.ParseMAC(outLinkDstStr)
	if err != nil {
		t.Fatal(err)
	}

	inLink, err := netlink.LinkByName(inLinkName)
	if err != nil {
		log.Fatalf("failed to fetch info about link %s: %v", inLinkName, err)
	}

	outLink, err := netlink.LinkByName(outLinkName)
	if err != nil {
		log.Fatalf("failed to fetch info about link %s: %v", outLinkName, err)
	}

	forwardL2(true, inLink, inLinkQueueID, inLinkDst, outLink, outLinkQueueID, outLinkDst)
}
