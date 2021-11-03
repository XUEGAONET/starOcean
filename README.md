# starOcean

## 使用方法

在使用本项目前，务必先进入`xsk`目录下，打开`generate.go`文件，找到需要的eBPF程序，使用对应的`go generate`程序进行代码生成。 已有的编译后的eBPF程序不一定是期望的，因此请一定重新编译。

## 阅读更多

* AF_XDP, The Linux Kernel. https://01.org/linuxgraphics/gfx-docs/drm/networking/af_xdp.html
* eBPF maps, Prototype Kernel. https://prototype-kernel.readthedocs.io/en/latest/bpf/ebpf_maps.html
* AF_XDP技术详解, REXROCK. https://rexrock.github.io/post/af_xdp1/
* Accelerating networking with AF_XDP, LWN. https://lwn.net/Articles/750845/
* eBPF XDP: The Basics and a Quick Tutorial, Tigera, Inc.. https://www.tigera.io/learn/guides/ebpf/ebpf-xdp/
* Integrating AF_XDP into DPDK,
  DPDK. https://www.dpdk.org/wp-content/uploads/sites/35/2019/07/14-AF_XDP-dpdk-summit-china-2019.pdf
* The Path to DPDK Speeds for AF XDP. http://vger.kernel.org/lpc_net2018_talks/lpc18_paper_af_xdp_perf-v2.pdf
* XDP卸载VxLAN参考. https://gitlab.com/mwiget/crpd-l2tpv3-xdp/-/blob/master/xdp/xdp_router.c
* eBPF程序转Go语言（binding）. https://github.com/cilium/ebpf/tree/master/cmd/bpf2go

