package ed448

import (
	"crypto/rand"
	"flag"
	mrand "math/rand"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func TestDevel(t *testing.T) {
	_ = mrand.Int()

	// private := PrivateKey{
	// 	0x6c, 0x82, 0xa5, 0x62, 0xcb, 0x80, 0x8d, 0x10, 0xd6, 0x32, 0xbe, 0x89, 0xc8, 0x51, 0x3e, 0xbf,
	// 	0x6c, 0x92, 0x9f, 0x34, 0xdd, 0xfa, 0x8c, 0x9f, 0x63, 0xc9, 0x96, 0x0e, 0xf6, 0xe3, 0x48, 0xa3,
	// 	0x52, 0x8c, 0x8a, 0x3f, 0xcc, 0x2f, 0x04, 0x4e, 0x39, 0xa3, 0xfc, 0x5b, 0x94, 0x49, 0x2f, 0x8f,
	// 	0x03, 0x2e, 0x75, 0x49, 0xa2, 0x00, 0x98, 0xf9, 0x5b,
	// }
	// sig := []byte{
	// 	0x53, 0x3a, 0x37, 0xf6, 0xbb, 0xe4, 0x57, 0x25, 0x1f, 0x02, 0x3c, 0x0d, 0x88, 0xf9, 0x76, 0xae,
	// 	0x2d, 0xfb, 0x50, 0x4a, 0x84, 0x3e, 0x34, 0xd2, 0x07, 0x4f, 0xd8, 0x23, 0xd4, 0x1a, 0x59, 0x1f,
	// 	0x2b, 0x23, 0x3f, 0x03, 0x4f, 0x62, 0x82, 0x81, 0xf2, 0xfd, 0x7a, 0x22, 0xdd, 0xd4, 0x7d, 0x78,
	// 	0x28, 0xc5, 0x9b, 0xd0, 0xa2, 0x1b, 0xfd, 0x39, 0x80, 0xff, 0x0d, 0x20, 0x28, 0xd4, 0xb1, 0x8a,
	// 	0x9d, 0xf6, 0x3e, 0x00, 0x6c, 0x5d, 0x1c, 0x2d, 0x34, 0x5b, 0x92, 0x5d, 0x8d, 0xc0, 0x0b, 0x41,
	// 	0x04, 0x85, 0x2d, 0xb9, 0x9a, 0xc5, 0xc7, 0xcd, 0xda, 0x85, 0x30, 0xa1, 0x13, 0xa0, 0xf4, 0xdb,
	// 	0xb6, 0x11, 0x49, 0xf0, 0x5a, 0x73, 0x63, 0x26, 0x8c, 0x71, 0xd9, 0x58, 0x08, 0xff, 0x2e, 0x65,
	// 	0x26, 0x00,
	// }
	// k := NewKeyFromSeed(private)
	// t.Logf("pk: %v\n", printScalar(k.GetPrivate()))
	// t.Logf("pk: %v\n", printScalar(k.GetPublic()))
	// ss := Sign(k, []byte(""), []byte(""))
	// ok := Verify(k.GetPublic(), []byte(""), []byte(""), ss)
	// t.Logf("verify: %v\n", ok)
}

func randomPoint(P *pointR1) {
	k := make([]byte, Size)
	_, _ = rand.Read(k[:])
	P.fixedMult(k)
}

func TestPoint(t *testing.T) {
	testTimes := 1 << 10

	t.Run("add", func(t *testing.T) {
		var P pointR1
		var Q pointR1
		var R pointR2
		for i := 0; i < testTimes; i++ {
			randomPoint(&P)
			_16P := P
			R.fromR1(&P)
			// 16P = 2^4P
			for j := 0; j < 4; j++ {
				_16P.double()
			}
			// 16P = P+P...+P
			Q.SetIdentity()
			for j := 0; j < 16; j++ {
				Q.add(&R)
			}

			got := _16P.isEqual(&Q)
			want := true
			if got != want {
				test.ReportError(t, got, want, P)
			}
		}
	})
	t.Run("fixed", func(t *testing.T) {
		var P, Q, R pointR1
		k := make([]byte, Size)
		l := make([]byte, Size)
		for i := 0; i < testTimes; i++ {
			randomPoint(&P)
			_, _ = rand.Read(k[:])
			k[Size-1] = 0

			Q.fixedMult(k[:])
			R.doubleMult(&P, k[:], l[:])

			got := Q.isEqual(&R)
			want := true
			if got != want {
				test.ReportError(t, got, want, P, k)
			}
		}
	})
}

var runLongBench = flag.Bool("long", false, "runs longer benchmark")

func BenchmarkPoint(b *testing.B) {
	if !*runLongBench {
		b.Log("Skipped one long bench, add -long flag to run longer bench")
		b.SkipNow()
	}

	k := make([]byte, Size)
	l := make([]byte, Size)
	_, _ = rand.Read(k)
	_, _ = rand.Read(l)

	var P pointR1
	var Q pointR2
	var R pointR3
	randomPoint(&P)
	Q.fromR1(&P)
	b.Run("toAffine", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			P.toAffine()
		}
	})
	b.Run("double", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			P.double()
		}
	})
	b.Run("mixadd", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			P.mixAdd(&R)
		}
	})
	b.Run("add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			P.add(&Q)
		}
	})
	b.Run("fixedMult", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			P.fixedMult(k)
		}
	})
	b.Run("doubleMult", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			P.doubleMult(&P, k, l)
		}
	})
}
