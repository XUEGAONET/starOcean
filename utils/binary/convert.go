package binary

func Swap16(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

func Swap32(i uint32) uint32 {
	b0 := (i & 0x000000ff) << 24
	b1 := (i & 0x0000ff00) << 8
	b2 := (i & 0x00ff0000) >> 8
	b3 := (i & 0xff000000) >> 24

	return b0 | b1 | b2 | b3
}
