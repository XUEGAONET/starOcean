package bd

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

func TestNewFDB(t *testing.T) {
	gcWait := time.Second * 5
	fdb := NewFDB(gcWait)
	defer fdb.Close()

	assert.Equal(t, 0, fdb.TraceEntryCount())
}

func TestRCUFDB_Override(t *testing.T) {
	gcWait := time.Second * 1
	fdb := NewFDB(gcWait)
	defer fdb.Close()

	assert.Equal(t, 0, fdb.TraceEntryCount())
	fdb.Override(generateKV(1))
	time.Sleep(gcWait)
	time.Sleep(gcWait)
	assert.Equal(t, 1, fdb.TraceEntryCount())

	for i := uint16(0); i < 1000; i++ {
		fdb.Override(generateKV(i))
	}
	time.Sleep(gcWait)
	time.Sleep(gcWait)
	assert.Equal(t, 1000, fdb.TraceEntryCount())

	for i := uint16(0); i < 4000; i++ {
		fdb.Override(generateKV(i))
	}
	time.Sleep(gcWait)
	time.Sleep(gcWait)
	assert.Equal(t, 4000, fdb.TraceEntryCount())

	for i := uint16(0); i < 10000; i++ {
		fdb.Override(generateKV(i))
	}
	time.Sleep(gcWait)
	time.Sleep(gcWait)
	assert.Equal(t, 10000, fdb.TraceEntryCount())
}

func TestRCUFDB_Delete(t *testing.T) {
	gcWait := time.Second * 1
	fdb := NewFDB(gcWait)
	defer fdb.Close()

	assert.Equal(t, 0, fdb.TraceEntryCount())

	for i := uint16(0); i < 1000; i++ {
		fdb.Override(generateKV(i))
	}
	time.Sleep(gcWait)
	time.Sleep(gcWait)
	assert.Equal(t, 1000, fdb.TraceEntryCount())

	addr, _ := generateKV(1)
	fdb.Delete(addr)
	time.Sleep(gcWait)
	time.Sleep(gcWait)
	assert.Equal(t, 999, fdb.TraceEntryCount())
	var pointer *FDBEntry = nil
	assert.Equal(t, pointer, fdb.Get(addr))

	addr, _ = generateKV(2)
	assert.NotEqual(t, nil, fdb.Get(addr))
}

func BenchmarkRCUFDB_Edit(b *testing.B) {
	gcWait := time.Second * 1
	fdb := NewFDB(gcWait)
	defer fdb.Close()

	for i := uint16(0); i < 4000; i++ {
		fdb.Override(generateKV(i))
	}
	time.Sleep(gcWait)
	time.Sleep(gcWait)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key, _ := generateKV(uint16(i % 4000))
		entry := fdb.Get(key)
		if entry == nil {
			panic("nil pointer")
		}
	}
}

func BenchmarkFDBMutex(b *testing.B) {
	gcWait := time.Second * 1
	fdb := NewFDB(gcWait)
	defer fdb.Close()

	for i := uint16(0); i < 4000; i++ {
		fdb.Override(generateKV(i))
	}
	time.Sleep(gcWait)
	time.Sleep(gcWait)

	var lock sync.RWMutex

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key, _ := generateKV(uint16(i % 4000))
		lock.RLock()
		entry := fdb.Get(key)
		lock.RUnlock()
		if entry == nil {
			panic("nil pointer")
		}
	}
}

func (r *RCUFDB) TraceEntryCount() int {
	ptr := atomic.LoadUintptr(&r.instancePtr)
	fdb := *(*map[uint64]*FDBEntry)(unsafe.Pointer(ptr))
	return len(fdb)
}

func generateKV(num uint16) (net.HardwareAddr, *FDBEntry) {
	addr := net.HardwareAddr{0xEE, 0, 0, 0, 0, 0}
	*(*uint16)(unsafe.Pointer(&addr[4])) = num
	return addr, &FDBEntry{
		Dest: net.IP{
			0xfd, 0x80, 0, 0, 0, 0, 0, 0,
			0x11, 0x22, 0, 0, 0, 0, 0, 0x01,
		},
		DestPort: 999,
	}
}
