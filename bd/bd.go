package bd

import (
	"fmt"
	"os"
	"time"

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	tapdev "starOcean/pkg/tap"
)

const (
	_gcWaitSec = 30
)

// BridgeDomain 就是普通的TAP设备。
// 也考虑过，总归都是要分配skbuff，因此就没有使用eBPF。
type BridgeDomain struct {
	fdb       *RCUFDB
	linkedTap *os.File
}

// New 会新增一个分布式BD。
// 传入的name参数为tap接口的名称，需要在传入时已经完成创建和配置，否则会报错
func New(name string) (*BridgeDomain, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, errors.Wrap(err, "get link by name failed")
	}

	if link.Type() != "tuntap" {
		return nil, errors.Wrap(err, "invalid netlink type: not tuntap")
	}

	tap, ok := link.(*netlink.Tuntap)
	if !ok {
		return nil, fmt.Errorf("can not assert type")
	}

	if tap.Mode != unix.IFF_TAP {
		return nil, fmt.Errorf("invalid tuntap type: not tap")
	}

	if tap.Flags&netlink.TUNTAP_ONE_QUEUE != netlink.TUNTAP_ONE_QUEUE {
		return nil, fmt.Errorf("invalid tap property: not one queue")
	}

	f, err := tapdev.NewFile(name)
	if err != nil {
		return nil, err
	}

	return &BridgeDomain{
		fdb:       NewFDB(time.Second * _gcWaitSec),
		linkedTap: f,
	}, nil
}

func (bd *BridgeDomain) Close() {
	_ = bd.linkedTap.Close()
}

// Transmit 发包（写入到tap的，对应tap的rx）。
//
func (bd *BridgeDomain) Transmit(buf []byte) (int, error) {
	if bd.linkedTap == nil {
		return 0, nil
	}

	return bd.linkedTap.Write(buf)
}

//// Receive 收包（从tap读，对应tap的tx）。
//func (bd *BridgeDomain) Receive(buf []byte) (int, error) {
//	n, err := bd.linkedTap.Read(buf)
//	if err != nil {
//		return 0, err
//	}
//
//	// TODO: 增加分布式网关下MAC Learning支持
//
//	if n < layers.LengthEthernet {
//		return 0, ErrLengthFragment
//	}
//
//	eth := *(*layers.Ethernet)(&buf)
//	entry := bd.fdb.Get(eth.GetDstAddress())
//
//	if !ok && bd.localAddr != nil && bd.localPort != 0 {
//		value := FDBEntry{
//			Dest:     bd.localAddr,
//			DestPort: bd.localPort,
//		}
//		bd.fdb.Store(key, value)
//	}
//
//	return 0, nil
//}
