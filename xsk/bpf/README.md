# BPF程序

## 简介

该eBPF程序主要用于重定向需要的包到`AF_XDP`套接字中，交由Go程序进行处理，以提高性能（相比`AF_PACKET`）。

## 特性

该eBPF程序提供了如下这些特性。

* 网卡代答`ICMPv4 ECHO请求`
* 重定向所有目标端口为443的TCP报文到`AF_XDP`套接字
* 网卡层面拦截了除`ICMPv4 ECHO请求`及业务外所有报文
* 一定程度上能够缓解DDoS攻击。当网卡支持eBPF Offload时，可极大程度缓解

## 注意

在操作系统低层开发，会和传统网络多少有些差别或者问题，如下。

* 暂时无法计算ICMP校验和，会置0。IPv4包头的校验和还会正常计算
* 操作系统抓包仅能抓到业务报文，`ICMPv4 ECHO请求`由于在网卡层面已经代答，因此系统抓不到
* ARP请求会直接bypass到内核正常协议栈处理，毕竟ARP还是要的
* 暂不支持IPv6

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

## 简单测试

【加速后】
```bash
[root@TEST ~]# ping 192.168.2.1 -f -c 100000
PING 192.168.2.1 (192.168.2.1) 56(84) bytes of data.
.
--- 192.168.2.1 ping statistics ---
100000 packets transmitted, 99999 received, 0% packet loss, time 6905ms
rtt min/avg/max/mdev = 0.023/0.038/2.128/0.020 ms, ipg/ewma 0.069/0.037 ms

```

【加速前】
```bash
[root@TEST ~]# ping 192.168.2.1 -f -c 100000
PING 192.168.2.1 (192.168.2.1) 56(84) bytes of data.

--- 192.168.2.1 ping statistics ---
100000 packets transmitted, 100000 received, 0% packet loss, time 7270ms
rtt min/avg/max/mdev = 0.028/0.047/3.027/0.020 ms, ipg/ewma 0.072/0.044 ms

```

【结论】虚拟化环境，多少还会有些偏差，至少在这个数据上，avg降低19.15%

