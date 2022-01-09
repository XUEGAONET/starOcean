package timer

import (
	"sync/atomic"
	"time"
)

// 内置定时器，以免系统时间突然出现跨度时，造成提前GC
var _time int64 = 0
var _started int32 = 0

func StartTimer() {
	if atomic.LoadInt32(&_started) != 0 {
		return
	}

	atomic.StoreInt32(&_started, 6)
	c := time.NewTicker(time.Second)
	go func() {
		for {
			<-c.C
			atomic.AddInt64(&_time, 1)
		}
	}()
}

func GetTimer() int64 {
	return atomic.LoadInt64(&_time)
}
