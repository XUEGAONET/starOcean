package bd

import (
	"net"
	"runtime"
	"sync/atomic"
	"time"
	"unsafe"
)

// TableSize 仅为默认值，在此值内可取得最效能，超出后仍然可以使用，但是效能会下降。
var TableSize = 4096

type FDBEntry struct {
	Dest     net.IP
	DestPort uint16
}

type RCUFDB struct {
	instance    *map[uint64]*FDBEntry
	instancePtr uintptr
	updateChan  chan *rcuFDBRequest
	closeChan   chan struct{}
}

type rcuFDBRequest struct {
	op    int
	key   uint64
	value *FDBEntry
}

const (
	opOverride = iota
	opDelete
)

func (r *RCUFDB) Override(addr net.HardwareAddr, entry *FDBEntry) {
	if len(addr) < 6 || entry == nil {
		return
	}

	req := rcuFDBRequest{
		op:    opOverride,
		key:   convertMacToU64(addr),
		value: entry,
	}

	r.updateChan <- &req
}

func (r *RCUFDB) Delete(addr net.HardwareAddr) {
	if len(addr) < 6 {
		return
	}

	req := rcuFDBRequest{
		op:    opDelete,
		key:   convertMacToU64(addr),
		value: nil,
	}

	r.updateChan <- &req
}

func (r *RCUFDB) Get(addr net.HardwareAddr) *FDBEntry {
	ptr := atomic.LoadUintptr(&r.instancePtr)
	if ptr == 0 {
		return nil
	}

	fdb := *(*map[uint64]*FDBEntry)(unsafe.Pointer(ptr))
	defer runtime.KeepAlive(fdb)

	key := convertMacToU64(addr)
	if key == 0 {
		return nil
	}
	res, ok := fdb[key]
	if !ok {
		return nil
	}

	return res
}

func (r *RCUFDB) updateLoop(waitTime time.Duration) {
	changed := make([]*rcuFDBRequest, TableSize)

	for {
		// 如果已经关闭了，就直接退出
		select {
		case <-r.closeChan:
			return
		default:
		}

		// 不浪费内存，相当于复用一片内存区域
		changed = changed[:0]
		changed = append(changed, <-r.updateChan)
		l := len(r.updateChan)
		for i := 0; i < l; i++ {
			changed = append(changed, <-r.updateChan)
		}
		// 此处要确保r.instance始终不为nil，否则会gg
		cloned := cloneFDB(r.instance)
		patchFDB(changed, cloned)

		// 主要思路就是，在进行指针替换操作时，临时禁用GC并在替换完成后等待一段时间，以免原本的还在使用中的数据被回收，造成panic。
		kp := r.instance
		r.instance = cloned
		atomic.StoreUintptr(&r.instancePtr, uintptr(unsafe.Pointer(cloned)))
		time.Sleep(waitTime)
		runtime.KeepAlive(kp)
	}
}

// patchFDB 会合并已有的RCU更改到传入的fdb中。
func patchFDB(reqs []*rcuFDBRequest, fdb *map[uint64]*FDBEntry) {
	for _, p := range reqs {
		switch p.op {
		case opOverride:
			(*fdb)[p.key] = p.value
		case opDelete:
			delete(*fdb, p.key)
		}
	}
}

func convertMacToU64(addr net.HardwareAddr) uint64 {
	if len(addr) < 6 {
		return 0
	}

	var res uint64
	(*(*[8]byte)(unsafe.Pointer(&res)))[0] = addr[0]
	(*(*[8]byte)(unsafe.Pointer(&res)))[1] = addr[1]
	(*(*[8]byte)(unsafe.Pointer(&res)))[2] = addr[2]
	(*(*[8]byte)(unsafe.Pointer(&res)))[3] = addr[3]
	(*(*[8]byte)(unsafe.Pointer(&res)))[4] = addr[4]
	(*(*[8]byte)(unsafe.Pointer(&res)))[5] = addr[5]

	return res
}

func convertU64ToMac(addr uint64) net.HardwareAddr {
	res := make(net.HardwareAddr, 6)
	res[0] = (*(*[8]byte)(unsafe.Pointer(&addr)))[0]
	res[1] = (*(*[8]byte)(unsafe.Pointer(&addr)))[1]
	res[2] = (*(*[8]byte)(unsafe.Pointer(&addr)))[2]
	res[3] = (*(*[8]byte)(unsafe.Pointer(&addr)))[3]
	res[4] = (*(*[8]byte)(unsafe.Pointer(&addr)))[4]
	res[5] = (*(*[8]byte)(unsafe.Pointer(&addr)))[5]
	return res
}

// NewFDB 会开启一个新的FDB。gcWait为关闭GC后的临时等待时间
func NewFDB(gcWait time.Duration) *RCUFDB {
	m := make(map[uint64]*FDBEntry, TableSize)

	i := RCUFDB{
		instance:    &m,
		instancePtr: uintptr(unsafe.Pointer(&m)),
		updateChan:  make(chan *rcuFDBRequest, TableSize),
		closeChan:   make(chan struct{}, 1),
	}

	go i.updateLoop(gcWait)

	return &i
}

func (r *RCUFDB) Close() {
	r.closeChan <- struct{}{}
}

// cloneFDB 只会克隆map，但是不会克隆FDBEntry指针指向的结构体。
func cloneFDB(ori *map[uint64]*FDBEntry) *map[uint64]*FDBEntry {
	res := make(map[uint64]*FDBEntry, TableSize)

	for k, v := range *ori {
		res[k] = v
	}

	return &res
}
