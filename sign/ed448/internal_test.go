package ed448

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/internal/conv"
	"github.com/cloudflare/circl/internal/test"
)

func TestCalculateS(t *testing.T) {
	const testTimes = 1 << 10
	s := make([]byte, Size)
	k := make([]byte, Size)
	r := make([]byte, Size)
	a := make([]byte, Size)
	orderBig := conv.BytesLe2BigInt(order[:])

	for i := 0; i < testTimes; i++ {
		_, _ = rand.Read(k[:])
		_, _ = rand.Read(r[:])
		_, _ = rand.Read(a[:])
		bigK := conv.BytesLe2BigInt(k[:])
		bigR := conv.BytesLe2BigInt(r[:])
		bigA := conv.BytesLe2BigInt(a[:])

		calculateS(s, r, k, a)
		got := conv.BytesLe2BigInt(s[:])

		bigK.Mul(bigK, bigA).Add(bigK, bigR)
		want := bigK.Mod(bigK, orderBig)

		if got.Cmp(want) != 0 {
			test.ReportError(t, got, want, k, r, a)
		}
	}
}

func TestReduction(t *testing.T) {
	const testTimes = 1 << 10
	var x, y [Size * 2]byte
	orderBig := conv.BytesLe2BigInt(order[:])

	for i := 0; i < testTimes; i++ {
		for _, j := range []int{Size, 2 * Size} {
			_, _ = rand.Read(x[:j])
			bigX := conv.BytesLe2BigInt(x[:j])
			copy(y[:j], x[:j])

			reduceModOrder(y[:j])
			got := conv.BytesLe2BigInt(y[:])

			want := bigX.Mod(bigX, orderBig)

			if got.Cmp(want) != 0 {
				test.ReportError(t, got, want, x)
			}
		}
	}
}

func TestRangeOrder(t *testing.T) { t.SkipNow() }
