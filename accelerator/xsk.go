// Copyright 2019 Asavie Technologies Ltd. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.
//
// ↑ 原版代码性能挺拉胯的，但是遵守规则，还是留着许可证吧

package accelerator

import (
	"fmt"
	"reflect"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// NewSocket 将会创建新的AF_XDP套接字。
func NewSocket(Ifindex int, QueueID int, options *SocketOptions) (xsk *Socket, err error) {
	if options == nil {
		return nil, fmt.Errorf("SocketOptions is a nil pointer")
	}

	xsk = &Socket{fd: -1, ifindex: Ifindex, options: *options}
	xsk.numFillRingDescMask = uint32(options.NumFillRingDesc) - 1
	xsk.numCompletionRingDescMask = uint32(options.NumCompletionRingDesc) - 1
	xsk.numRxRingDescMask = uint32(options.NumRxRingDesc) - 1
	xsk.numTxRingDescMask = uint32(options.NumTxRingDesc) - 1

	xsk.fd, err = syscall.Socket(unix.AF_XDP, syscall.SOCK_RAW, 0)
	if err != nil {
		return nil, errors.Wrap(err, "syscall.Socket create xdp fd failed")
	}

	flag := syscall.MAP_PRIVATE | syscall.MAP_ANONYMOUS | syscall.MAP_POPULATE | unix.MAP_HUGETLB
	memBufSize := options.NumFrame*options.SizeFrame + 4*options.NumFrame*int(unsafe.Sizeof(Desc{}))

	memBuf, err := syscall.Mmap(-1, 0, memBufSize,
		syscall.PROT_READ|syscall.PROT_WRITE, flag)
	if err != nil {
		xsk.Close()
		return nil, errors.Wrap(err, "syscall.Mmap umem failed")
	}

	logrus.WithField("module", "xsk").Infof("Used hugepage size: %dKB", memBufSize/1024)

	xsk.umem = memBuf[:options.NumFrame*options.SizeFrame]

	var sh *reflect.SliceHeader

	sh = (*reflect.SliceHeader)(unsafe.Pointer(&xsk.fillDescs))
	sh.Data = uintptr(unsafe.Pointer(&memBuf[options.NumFrame*options.SizeFrame+0*options.NumFrame*int(unsafe.Sizeof(Desc{}))]))
	sh.Len = options.NumFrame
	sh.Cap = options.NumFrame

	sh = (*reflect.SliceHeader)(unsafe.Pointer(&xsk.completeDescs))
	sh.Data = uintptr(unsafe.Pointer(&memBuf[options.NumFrame*options.SizeFrame+1*options.NumFrame*int(unsafe.Sizeof(Desc{}))]))
	sh.Len = options.NumFrame
	sh.Cap = options.NumFrame

	sh = (*reflect.SliceHeader)(unsafe.Pointer(&xsk.rxDescs))
	sh.Data = uintptr(unsafe.Pointer(&memBuf[options.NumFrame*options.SizeFrame+2*options.NumFrame*int(unsafe.Sizeof(Desc{}))]))
	sh.Len = options.NumFrame
	sh.Cap = options.NumFrame

	sh = (*reflect.SliceHeader)(unsafe.Pointer(&xsk.txDescs))
	sh.Data = uintptr(unsafe.Pointer(&memBuf[options.NumFrame*options.SizeFrame+3*options.NumFrame*int(unsafe.Sizeof(Desc{}))]))
	sh.Len = options.NumFrame
	sh.Cap = options.NumFrame

	xdpUmemReg := unix.XDPUmemReg{
		Addr:     uint64(uintptr(unsafe.Pointer(&xsk.umem[0]))),
		Len:      uint64(len(xsk.umem)),
		Size:     uint32(options.SizeFrame),
		Headroom: 0,
	}

	var errno syscall.Errno
	var rc uintptr

	rc, _, errno = unix.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(xsk.fd),
		unix.SOL_XDP, unix.XDP_UMEM_REG,
		uintptr(unsafe.Pointer(&xdpUmemReg)),
		unsafe.Sizeof(xdpUmemReg), 0)
	if rc != 0 {
		xsk.Close()
		return nil, errors.Wrap(errno, "SYS_SETSOCKOPT XDP_UMEM_REG failed")
	}

	err = syscall.SetsockoptInt(xsk.fd, unix.SOL_XDP, unix.XDP_UMEM_FILL_RING,
		options.NumFillRingDesc)
	if err != nil {
		xsk.Close()
		return nil, errors.Wrap(err, "SYS_SETSOCKOPT XDP_UMEM_FILL_RING failed")
	}

	err = unix.SetsockoptInt(xsk.fd, unix.SOL_XDP, unix.XDP_UMEM_COMPLETION_RING,
		options.NumCompletionRingDesc)
	if err != nil {
		xsk.Close()
		return nil, errors.Wrap(err, "SYS_SETSOCKOPT XDP_UMEM_COMPLETION_RING failed")
	}

	err = unix.SetsockoptInt(xsk.fd, unix.SOL_XDP, unix.XDP_RX_RING,
		options.NumRxRingDesc)
	if err != nil {
		xsk.Close()
		return nil, errors.Wrap(err, "SYS_SETSOCKOPT XDP_RX_RING failed")
	}

	err = unix.SetsockoptInt(xsk.fd, unix.SOL_XDP, unix.XDP_TX_RING,
		options.NumTxRingDesc)
	if err != nil {
		xsk.Close()
		return nil, errors.Wrap(err, "SYS_SETSOCKOPT XDP_TX_RING failed")
	}

	var offsets unix.XDPMmapOffsets
	var vallen uint32
	vallen = uint32(unsafe.Sizeof(offsets))
	rc, _, errno = unix.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(xsk.fd),
		unix.SOL_XDP, unix.XDP_MMAP_OFFSETS,
		uintptr(unsafe.Pointer(&offsets)),
		uintptr(unsafe.Pointer(&vallen)), 0)
	if rc != 0 {
		xsk.Close()
		return nil, errors.Wrap(errno, "SYS_GETSOCKOPT XDP_MMAP_OFFSETS failed")
	}

	// process fill ring
	fillRingSlice, err := syscall.Mmap(xsk.fd, unix.XDP_UMEM_PGOFF_FILL_RING,
		int(offsets.Fr.Desc+uint64(options.NumFillRingDesc)*uint64(unsafe.Sizeof(uint64(0)))),
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_SHARED|syscall.MAP_POPULATE)
	if err != nil {
		xsk.Close()
		return nil, errors.Wrap(err, "syscall.Mmap fill ring failed")
	}
	xsk.fillRing.Producer = (*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(&fillRingSlice[0])) + uintptr(offsets.Fr.Producer)))
	xsk.fillRing.Consumer = (*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(&fillRingSlice[0])) + uintptr(offsets.Fr.Consumer)))
	sh = (*reflect.SliceHeader)(unsafe.Pointer(&xsk.fillRing.Descs))
	sh.Data = uintptr(unsafe.Pointer(&fillRingSlice[0])) + uintptr(offsets.Fr.Desc)
	sh.Len = options.NumFillRingDesc
	sh.Cap = options.NumFillRingDesc

	// process completion ring
	completionRingSlice, err := syscall.Mmap(xsk.fd, unix.XDP_UMEM_PGOFF_COMPLETION_RING,
		int(offsets.Cr.Desc+uint64(options.NumCompletionRingDesc)*uint64(unsafe.Sizeof(uint64(0)))),
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_SHARED|syscall.MAP_POPULATE)
	if err != nil {
		xsk.Close()
		return nil, errors.Wrap(err, "syscall.Mmap completion ring failed")
	}
	xsk.completionRing.Producer = (*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(&completionRingSlice[0])) + uintptr(offsets.Cr.Producer)))
	xsk.completionRing.Consumer = (*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(&completionRingSlice[0])) + uintptr(offsets.Cr.Consumer)))
	sh = (*reflect.SliceHeader)(unsafe.Pointer(&xsk.completionRing.Descs))
	sh.Data = uintptr(unsafe.Pointer(&completionRingSlice[0])) + uintptr(offsets.Cr.Desc)
	sh.Len = options.NumCompletionRingDesc
	sh.Cap = options.NumCompletionRingDesc

	// process rx ring
	rxRingSlice, err := syscall.Mmap(xsk.fd, unix.XDP_PGOFF_RX_RING,
		int(offsets.Rx.Desc+uint64(options.NumRxRingDesc)*uint64(unsafe.Sizeof(Desc{}))),
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_SHARED|syscall.MAP_POPULATE)
	if err != nil {
		xsk.Close()
		return nil, errors.Wrap(err, "syscall.Mmap rx ring failed")
	}
	xsk.rxRing.Producer = (*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(&rxRingSlice[0])) + uintptr(offsets.Rx.Producer)))
	xsk.rxRing.Consumer = (*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(&rxRingSlice[0])) + uintptr(offsets.Rx.Consumer)))
	sh = (*reflect.SliceHeader)(unsafe.Pointer(&xsk.rxRing.Descs))
	sh.Data = uintptr(unsafe.Pointer(&rxRingSlice[0])) + uintptr(offsets.Rx.Desc)
	sh.Len = options.NumRxRingDesc
	sh.Cap = options.NumRxRingDesc

	// process tx ring
	txRingSlice, err := syscall.Mmap(xsk.fd, unix.XDP_PGOFF_TX_RING,
		int(offsets.Tx.Desc+uint64(options.NumTxRingDesc)*uint64(unsafe.Sizeof(Desc{}))),
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_SHARED|syscall.MAP_POPULATE)
	if err != nil {
		xsk.Close()
		return nil, errors.Wrap(err, "syscall.Mmap tx ring failed")
	}
	xsk.txRing.Producer = (*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(&txRingSlice[0])) + uintptr(offsets.Tx.Producer)))
	xsk.txRing.Consumer = (*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(&txRingSlice[0])) + uintptr(offsets.Tx.Consumer)))
	sh = (*reflect.SliceHeader)(unsafe.Pointer(&xsk.txRing.Descs))
	sh.Data = uintptr(unsafe.Pointer(&txRingSlice[0])) + uintptr(offsets.Tx.Desc)
	sh.Len = options.NumTxRingDesc
	sh.Cap = options.NumTxRingDesc

	sa := unix.SockaddrXDP{
		Flags:   DefaultSocketFlags,
		Ifindex: uint32(Ifindex),
		QueueID: uint32(QueueID),
	}
	if err = unix.Bind(xsk.fd, &sa); err != nil {
		xsk.Close()
		return nil, errors.Wrap(err, "syscall.Bind SockaddrXDP failed")
	}

	return xsk, nil
}

// Fill 会将Desc的Addr填充到对应FR中的Desc中，以准备接收。
// 其不会检查空余数量，请务必使用 GetFreeFillDescs 获取并传入。
func (xsk *Socket) Fill(descs []Desc) int {
	if descs == nil {
		return 0
	}

	prod := *xsk.fillRing.Producer
	for _, desc := range descs {
		xsk.fillRing.Descs[prod&xsk.numFillRingDescMask] = desc.Addr
		prod++
	}
	*xsk.fillRing.Producer = prod

	xsk.countFilled += uint64(len(descs))

	return len(descs)
}

// Receive 会接收n个Desc并返回。
// 其不会检查RxRing中真正收到了多少，因此请务必使用 Poll 获取到正确的值之后再传入。
func (xsk *Socket) Receive(n int) []Desc {
	descs := xsk.rxDescs[:0]
	cons := *xsk.rxRing.Consumer
	for i := 0; i < n; i++ {
		descs = append(descs, xsk.rxRing.Descs[cons&xsk.numRxRingDescMask])
		cons++
	}
	*xsk.rxRing.Consumer = cons

	xsk.countReceived += uint64(n)

	return descs
}

// Transmit 会使用给的Desc发送。
// 其不会检查TxRing中还有多少空位，因此请务必使用 GetFreeTransmitDescs 取得的，以防止出现错误。
// 如需共享UMEM，请自行获取空闲容量，截取确保合法的情况下，再使用 Transmit。
func (xsk *Socket) Transmit(descs []Desc) {
	prod := *xsk.txRing.Producer
	for i, _ := range descs {
		xsk.txRing.Descs[prod&xsk.numTxRingDescMask] = descs[i]
		prod++
	}
	*xsk.txRing.Producer = prod

	xsk.countTransmitted += uint64(len(descs))

	var rc uintptr
	var errno syscall.Errno
SEND:
	rc, _, errno = unix.Syscall6(syscall.SYS_SENDTO,
		uintptr(xsk.fd),
		0, 0,
		uintptr(unix.MSG_DONTWAIT),
		0, 0)
	if rc != 0 {
		switch errno {
		case unix.EINTR:
			goto SEND
		case unix.EAGAIN:
			return
		case unix.EBUSY: // completed but not sent
			return
		default:
			logrus.WithField("module", "xsk").Errorf("sendto failed with rc=%d and errno=%d", rc, errno)
			return
		}
	}

	return
}

func (xsk *Socket) FD() int {
	return xsk.fd
}

// Poll 将会阻塞直到接收到相关的事件。
// 返回的num均需要进行消费，否则会产生问题。
func (xsk *Socket) Poll(timeout int) (numReceived int, numCompleted int, err error) {
	var events int16
	// fillRing有未被消费的
	if *xsk.fillRing.Producer-*xsk.fillRing.Consumer > 0 {
		events |= unix.POLLIN
	}
	// txRing中有未被消费的
	if *xsk.txRing.Producer-*xsk.txRing.Consumer > 0 {
		events |= unix.POLLOUT
	}
	if events == 0 {
		return
	}

	pfd := unix.PollFd{
		Fd:      int32(xsk.fd),
		Events:  events,
		Revents: 0,
	}
	pfdLen := 1
POLL:
	_, _, errno := unix.Syscall(unix.SYS_POLL, uintptr(unsafe.Pointer(&pfd)), uintptr(pfdLen), uintptr(timeout))
	if errno != 0 {
		switch errno {
		case unix.EINTR:
			goto POLL
		default:
			return 0, 0, fmt.Errorf("SYS_POLL failed: fd=%d, events=%d, errno=%d",
				xsk.fd, events, errno)
		}
	}

	numReceived = xsk.NumReceived()
	numCompleted = xsk.NumCompleted()

	return
}

// GetFreeFillDescs 使用UMEM中的前一半的空间返回Desc，返回的数量可能和n不同，以返回的Desc数量为准。
// 一定要使用 Receive 消费。
// GetFreeFillDescs 只根据指针位置生产Desc，不挪动指针。挪动指针将在 Fill 阶段进行。
func (xsk *Socket) GetFreeFillDescs(n int) []Desc {
	free := xsk.NumFreeFillSlots()

	// 没有空余时直接返回
	if free == 0 {
		return nil
	}

	if n > free {
		n = free
	}
	descs := xsk.fillDescs[:0]

	prod := int(*xsk.fillRing.Producer)
	for i := 0; i < n; i++ {
		descs = append(descs, Desc{
			Addr: uint64(xsk.options.SizeFrame * (prod + i) & int(xsk.numFillRingDescMask)),
			Len:  uint32(xsk.options.SizeFrame),
		})
	}
	return descs
}

// GetFreeTransmitDescs 使用UMEM中的后一半的空间返回Desc，返回的数量可能和n不同，以返回的Desc数量为准。
// 一定要使用 Complete 消费。
// GetFreeTransmitDescs 只根据指针位置生产Desc，不挪动指针。挪动指针将在 Transmit 阶段进行。
func (xsk *Socket) GetFreeTransmitDescs(n int) []Desc {
	free := xsk.NumFreeTxSlots()

	// 没有空余时直接返回
	if free == 0 {
		return nil
	}

	if n > free {
		n = free
	}
	descs := xsk.txDescs[:0]

	prod := int(*xsk.txRing.Producer)
	for i := 0; i < n; i++ {
		descs = append(descs, Desc{
			Addr: uint64(xsk.options.SizeFrame * (xsk.options.NumFrame/2 + (prod+i)&int(xsk.numTxRingDescMask))),
			Len:  uint32(xsk.options.SizeFrame),
		})
	}

	return descs
}

// GetFrame 会返回一个切片，请在 SizeFrame 的长度范围内使用。
func (xsk *Socket) GetFrame(d Desc) []byte {
	return xsk.umem[d.Addr : d.Addr+uint64(d.Len)]
}

func (xsk *Socket) Close() error {
	var allErrors []error
	var err error

	if xsk.fd != -1 {
		if err = unix.Close(xsk.fd); err != nil {
			allErrors = append(allErrors, errors.Wrap(err, "failed to close XDP socket"))
		}
		xsk.fd = -1

		var sh *reflect.SliceHeader

		sh = (*reflect.SliceHeader)(unsafe.Pointer(&xsk.completionRing.Descs))
		sh.Data = uintptr(0)
		sh.Len = 0
		sh.Cap = 0

		sh = (*reflect.SliceHeader)(unsafe.Pointer(&xsk.txRing.Descs))
		sh.Data = uintptr(0)
		sh.Len = 0
		sh.Cap = 0

		sh = (*reflect.SliceHeader)(unsafe.Pointer(&xsk.rxRing.Descs))
		sh.Data = uintptr(0)
		sh.Len = 0
		sh.Cap = 0

		sh = (*reflect.SliceHeader)(unsafe.Pointer(&xsk.fillRing.Descs))
		sh.Data = uintptr(0)
		sh.Len = 0
		sh.Cap = 0
	}

	if xsk.umem != nil {
		if err := syscall.Munmap(xsk.umem); err != nil {
			allErrors = append(allErrors, errors.Wrap(err, "failed to unmap the UMEM"))
		}
		xsk.umem = nil
	}

	if len(allErrors) > 0 {
		return allErrors[0]
	}

	return nil
}

// Complete 将会消费掉 Transmit 阶段产生的Desc。
func (xsk *Socket) Complete(n int) {
	*xsk.completionRing.Consumer += uint32(n)
	xsk.countCompleted += uint64(n)
}

// NumFreeFillSlots 获取FillRing中的空位置数量
func (xsk *Socket) NumFreeFillSlots() int {
	prod := *xsk.fillRing.Producer
	cons := *xsk.fillRing.Consumer
	max := uint32(xsk.options.NumFillRingDesc)

	n := max - (prod - cons)
	if n > max {
		n = max
	}

	return int(n)
}

// NumFreeTxSlots 获取TxRing中的空位置数量
func (xsk *Socket) NumFreeTxSlots() int {
	prod := *xsk.txRing.Producer
	cons := *xsk.txRing.Consumer
	max := uint32(xsk.options.NumTxRingDesc)

	n := max - (prod - cons)
	if n > max {
		n = max
	}

	return int(n)
}

// NumReceived 获取RxRing中的元素数量，注意不是空位置。
func (xsk *Socket) NumReceived() int {
	prod := *xsk.rxRing.Producer
	cons := *xsk.rxRing.Consumer
	max := uint32(xsk.options.NumRxRingDesc)

	n := prod - cons
	if n > max {
		n = max
	}

	return int(n)
}

// NumCompleted 获取CompleteRing中的元素数量，注意不是空位置。
func (xsk *Socket) NumCompleted() int {
	prod := *xsk.completionRing.Producer
	cons := *xsk.completionRing.Consumer
	max := uint32(xsk.options.NumCompletionRingDesc)

	n := prod - cons
	if n > max {
		n = max
	}

	return int(n)
}

func (xsk *Socket) Stats() (Stats, error) {
	var stats Stats
	var size uint64

	stats.Filled = xsk.countFilled
	stats.Completed = xsk.countCompleted
	stats.Received = xsk.countReceived
	stats.Transmitted = xsk.countTransmitted

	size = uint64(unsafe.Sizeof(stats.KernelStats))
	rc, _, errno := unix.Syscall6(syscall.SYS_GETSOCKOPT,
		uintptr(xsk.fd),
		unix.SOL_XDP, unix.XDP_STATISTICS,
		uintptr(unsafe.Pointer(&stats.KernelStats)),
		uintptr(unsafe.Pointer(&size)), 0)
	if rc != 0 {
		return stats, errors.Wrap(errno, "SYS_GETSOCKOPT XDP_STATISTICS failed")
	}
	return stats, nil
}
