package binary

import (
	"fmt"
	"testing"
)

func TestIsBigEndian(t *testing.T) {
	r := IsBigEndian()
	fmt.Println(r)
}
