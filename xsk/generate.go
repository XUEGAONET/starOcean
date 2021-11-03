package xsk

// Only support Little Endian
// 请务必不要在Big Endian的机器上使用，程序没有设计对其的支持

// 1. 生产使用
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2" xsk ./bpf/xsk.c
// 2. 测试ICMPv4处理 example/sendicmpv4
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2" xsk ./bpf/xsk_test_icmp.c
