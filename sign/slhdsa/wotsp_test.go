package slhdsa

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func mustRead(t testing.TB, size uint) (out []byte) {
	out = make([]byte, size)
	_, err := io.ReadFull(rand.Reader, out)
	if err != nil {
		t.Fatalf("rand reader error: %v", err)
	}
	return
}

func testWotsPlus(t *testing.T, s *state) {
	skSeed := mustRead(t, s.n)
	pkSeed := mustRead(t, s.n)
	msg := mustRead(t, s.n)

	var addr address
	addr.SetTypeAndClear(addressWotsHash)
	pk1 := s.wotsPkGen(skSeed, pkSeed, addr)
	test.CheckOk(len(pk1) == int(s.n),
		fmt.Sprintf("bad wots+ public key length: %v", len(pk1)), t)

	sig := s.wotsSign(msg, skSeed, pkSeed, addr)
	test.CheckOk(len(sig) == int(s.wotsLen()),
		fmt.Sprintf("bad wots+signature length: %v", len(sig)), t)
	for i := range sig {
		test.CheckOk(
			len(sig[i]) == int(s.n),
			fmt.Sprintf("bad length of wots+ signature's %v-th element: %v", i, len(sig[i])), t)
	}

	pk2 := s.wotsPkFromSig(sig, msg, pkSeed, addr)
	test.CheckOk(len(pk2) == int(s.n), fmt.Sprintf("bad wots+ public key length: %v", len(pk2)), t)

	if !bytes.Equal(pk1, pk2) {
		test.ReportError(t, pk1, pk2, skSeed, pkSeed, msg)
	}
}

func TestWotsPlus(t *testing.T) {
	for _, ins := range instances {
		state, err := ins.ins.newState()
		test.CheckNoErr(t, err, "failed to create a state")
		t.Run(state.name, func(tt *testing.T) { testWotsPlus(tt, state) })
	}
}

func benchmarkWotsPlus(b *testing.B, s *state) {
	skSeed := mustRead(b, s.n)
	pkSeed := mustRead(b, s.n)
	msg := mustRead(b, s.n)

	var addr address
	addr.SetTypeAndClear(addressWotsHash)
	sig := s.wotsSign(msg, skSeed, pkSeed, addr)

	b.Run("PkGen", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = s.wotsPkGen(skSeed, pkSeed, addr)
		}
	})

	b.Run("Sign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = s.wotsSign(msg, skSeed, pkSeed, addr)
		}
	})

	b.Run("PkFromSig", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = s.wotsPkFromSig(sig, msg, pkSeed, addr)
		}
	})
}

func BenchmarkWotsPlus(b *testing.B) {
	for _, ins := range instances {
		state, err := ins.ins.newState()
		test.CheckNoErr(b, err, "failed to create a state")
		b.Run(state.name, func(bb *testing.B) { benchmarkWotsPlus(bb, state) })
	}
}
