// Code generated by bpf2go; DO NOT EDIT.
// +build 386 amd64 amd64p32 arm arm64 mips64le mips64p32le mipsle ppc64le riscv64

package xsk

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadXsk returns the embedded CollectionSpec for xsk.
func loadXsk() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_XskBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load xsk: %w", err)
	}

	return spec, err
}

// loadXskObjects loads xsk and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//     *xskObjects
//     *xskPrograms
//     *xskMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadXskObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadXsk()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// xskSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type xskSpecs struct {
	xskProgramSpecs
	xskMapSpecs
}

// xskSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type xskProgramSpecs struct {
	XskProgram *ebpf.ProgramSpec `ebpf:"xsk_program"`
}

// xskMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type xskMapSpecs struct {
	IngressFilter *ebpf.MapSpec `ebpf:"ingress_filter"`
	LocalArpTable *ebpf.MapSpec `ebpf:"local_arp_table"`
	XsksMap       *ebpf.MapSpec `ebpf:"xsks_map"`
}

// xskObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadXskObjects or ebpf.CollectionSpec.LoadAndAssign.
type xskObjects struct {
	xskPrograms
	xskMaps
}

func (o *xskObjects) Close() error {
	return _XskClose(
		&o.xskPrograms,
		&o.xskMaps,
	)
}

// xskMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadXskObjects or ebpf.CollectionSpec.LoadAndAssign.
type xskMaps struct {
	IngressFilter *ebpf.Map `ebpf:"ingress_filter"`
	LocalArpTable *ebpf.Map `ebpf:"local_arp_table"`
	XsksMap       *ebpf.Map `ebpf:"xsks_map"`
}

func (m *xskMaps) Close() error {
	return _XskClose(
		m.IngressFilter,
		m.LocalArpTable,
		m.XsksMap,
	)
}

// xskPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadXskObjects or ebpf.CollectionSpec.LoadAndAssign.
type xskPrograms struct {
	XskProgram *ebpf.Program `ebpf:"xsk_program"`
}

func (p *xskPrograms) Close() error {
	return _XskClose(
		p.XskProgram,
	)
}

func _XskClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//go:embed xsk_bpfel.o
var _XskBytes []byte
