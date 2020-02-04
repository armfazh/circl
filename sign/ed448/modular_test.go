package ed448

import (
	mrand "math/rand"
	"testing"

	"github.com/cloudflare/circl/internal/conv"
)

func ones(x []byte) {
	for i := range x {
		x[i] = 0xFF
	}
}

func TestModular(t *testing.T) {
	_ = mrand.Int()
	Z := make([]byte, 2*Size)
	ones(Z)

	t.Logf("Z: %v\n", conv.BytesLe2Hex(Z))

	a := byte2uint(Z)
	res := byte2uint(residue)

	t.Logf("r(%v): %v\n", len(res), conv.UintLe2Hex(res))
	t.Logf("a(%v): %v\n", len(a), conv.UintLe2Hex(a))

	for i := 0; i < 3; i++ {
		a1, a0 := a[7:], a[0:7]
		a = add(a0, mul(a1, res))
		t.Logf("a(%v): %v\n", len(a), conv.UintLe2Hex(a))
	}
}

func BenchmarkModular(b *testing.B) {
	Z := make([]byte, 2*Size)
	ones(Z)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		order.reduce(Z)
	}
}
