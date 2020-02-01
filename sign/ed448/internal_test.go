package ed448

import (
	"crypto/rand"
	"math/big"
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
	var order big.Int
	order.SetString("3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3", 16)

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
		want := bigK.Mod(bigK, &order)

		if got.Cmp(want) != 0 {
			test.ReportError(t, got, want, k, r, a)
		}
	}
}

func TestReduction(t *testing.T) {
	const testTimes = 1 << 10
	var x, y [Size * 2]byte
	var order big.Int
	order.SetString("3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3", 16)

	for i := 0; i < testTimes; i++ {
		for _, j := range []int{Size, 2 * Size} {
			_, _ = rand.Read(x[:j])
			bigX := conv.BytesLe2BigInt(x[:j])
			copy(y[:j], x[:j])

			reduceModOrder(y[:j])
			got := conv.BytesLe2BigInt(y[:])

			want := bigX.Mod(bigX, &order)

			if got.Cmp(want) != 0 {
				test.ReportError(t, got, want, x)
			}
		}
	}
}

func TestRangeOrder(t *testing.T)     { t.SkipNow() }
func TestIsGreaterThanP(t *testing.T) { t.SkipNow() }
