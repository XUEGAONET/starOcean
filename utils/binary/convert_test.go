package binary

import (
	"fmt"
	"testing"
)

func TestSwap16(t *testing.T) {
	r := Swap16(3)
	fmt.Println(r)
	fmt.Printf("%x\n", r)
}

func TestSwap32(t *testing.T) {
	r := Swap32(0x12345678)
	fmt.Println(r)
	fmt.Printf("%x\n", r)
}
