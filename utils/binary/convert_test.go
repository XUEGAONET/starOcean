package binary

import (
	"fmt"
	"testing"
)

func TestHtons16(t *testing.T) {
	r := Htons16(3)
	fmt.Println(r)
}

func BenchmarkHtons16(b *testing.B) {
	Htons16(3)
}
