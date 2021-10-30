package checksum

// Calculate the TCP/IP checksum defined in rfc1071.  The passed-in csum is any
// initial checksum data that's already been computed.
// GRE, ICMPv4, TCP/IP can use it.
func TCPIPChecksum(data []byte, baseCSum uint32) uint16 {
	// 避免重复获取长度
	length := len(data)
	// 计算偶数部分
	for i := 0; i < length>>1; i++ {
		baseCSum += uint32(data[i*2])<<8 + uint32(data[i*2+1])
	}
	// 如果是奇数就把最后一位加上
	if length&0x01 == 0x01 {
		baseCSum += uint32(data[length]) << 8
	}
	for baseCSum > 0xffff {
		baseCSum = (baseCSum >> 16) + (baseCSum & 0xffff)
	}
	return ^uint16(baseCSum)
}
