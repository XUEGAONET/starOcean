package underlay

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-O2" ebpf ../bpf/underlay.c
