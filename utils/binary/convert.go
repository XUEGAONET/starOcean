package binary

func Htons16(i uint16) uint16 {
	if IsBigEndian() {
		return i
	} else {
		return (i<<8)&0xff00 | i>>8
	}
}
