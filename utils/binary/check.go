package binary

import "unsafe"

func IsBigEndian() bool {
	var i uint16 = 0x0001
	return (*[2]byte)(unsafe.Pointer(&i))[0] == 0x00
}
