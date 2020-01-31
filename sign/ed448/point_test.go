package ed448

import (
	"crypto/rand"
	"flag"
	"fmt"
	mrand "math/rand"
	"testing"

	"github.com/cloudflare/circl/internal/test"
	fp "github.com/cloudflare/circl/math/fp448"
)

func TestDevel(t *testing.T) {
	var P, Q pointR1
	randomPoint(&P)
	t.Logf("P: %v\n", P)

	m := make([]byte, Size)
	mrand.Read(m)
	sm := "m: 0x"
	for i := len(m) - 1; i >= 0; i-- {
		sm += fmt.Sprintf("%02x", m[i])
	}
	t.Logf(sm)
	Q.fixedMult(m)
	Q.toAffine()
	t.Logf("kP: %v\n", Q)
}

func randomPoint(P *pointR1) {
	// k := make([]byte, Size)
	// _, _ = rand.Read(k[:])
	// P.fixedMult(k)
	genX := fp.Elt{
		0x5e, 0xc0, 0x0c, 0xc7, 0x2b, 0xa8, 0x26, 0x26,
		0x8e, 0x93, 0x00, 0x8b, 0xe1, 0x80, 0x3b, 0x43,
		0x11, 0x65, 0xb6, 0x2a, 0xf7, 0x1a, 0xae, 0x12,
		0x64, 0xa4, 0xd3, 0xa3, 0x24, 0xe3, 0x6d, 0xea,
		0x67, 0x17, 0x0f, 0x47, 0x70, 0x65, 0x14, 0x9e,
		0xda, 0x36, 0xbf, 0x22, 0xa6, 0x15, 0x1d, 0x22,
		0xed, 0x0d, 0xed, 0x6b, 0xc6, 0x70, 0x19, 0x4f,
	}
	genY := fp.Elt{
		0x14, 0xfa, 0x30, 0xf2, 0x5b, 0x79, 0x08, 0x98,
		0xad, 0xc8, 0xd7, 0x4e, 0x2c, 0x13, 0xbd, 0xfd,
		0xc4, 0x39, 0x7c, 0xe6, 0x1c, 0xff, 0xd3, 0x3a,
		0xd7, 0xc2, 0xa0, 0x05, 0x1e, 0x9c, 0x78, 0x87,
		0x40, 0x98, 0xa3, 0x6c, 0x73, 0x73, 0xea, 0x4b,
		0x62, 0xc7, 0xc9, 0x56, 0x37, 0x20, 0x76, 0x88,
		0x24, 0xbc, 0xb6, 0x6e, 0x71, 0x46, 0x3f, 0x69,
	}
	copy(P.x[:], genX[:])
	copy(P.y[:], genY[:])
	fp.SetOne(&P.z)
	P.ta = P.x
	P.tb = P.y
	iso := deg4isogeny{}
	iso.Push(P)
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
	// t.Run("fixed", func(t *testing.T) {
	// 	var P pointR1
	// 	k := make([]byte, Size)
	// 	l := make([]byte, Size)
	// 	for i := 0; i < testTimes; i++ {
	// 		randomPoint(&P)
	// 		_, _ = rand.Read(k[:])
	// 		Q := P
	// 		R := P
	//
	// 		Q.fixedMult(k[:])
	// 		R.doubleMult(&P, k[:], l[:])
	//
	// 		got := Q.isEqual(&R)
	// 		want := true
	// 		if got != want {
	// 			test.ReportError(t, got, want, P, k)
	// 		}
	// 	}
	// })
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
