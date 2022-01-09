# BPF程序

## 简介

该eBPF程序主要用于重定向需要的包到`AF_XDP`套接字中，交由Go程序进行处理，以提高性能（相比`AF_PACKET`）。

## 操作命令

```bash
# compile to .o
clang -O2 -target bpf -c xsk.c -o xsk.o
# compile to .s
clang -O2 -target bpf -c xsk.c -S -o xsk.s

# detach
sudo ip link set dev ens19 xdp off

# attach
sudo ip link set dev ens19 xdp obj xsk.o sec xsk_program
# also you can use cilium ebpf loader
```
