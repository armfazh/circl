package slhdsa

import (
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func testInternal(t *testing.T, s *state) {
	skSeed := mustRead(t, s.n)
	skPrf := mustRead(t, s.n)
	pkSeed := mustRead(t, s.n)
	msg := mustRead(t, s.m)
	addRand := mustRead(t, s.n)

	sk, pk := s.slhKeyGenInternal(skSeed, skPrf, pkSeed)

	sig, err := s.slhSignInternal(sk, msg, addRand)
	test.CheckNoErr(t, err, "slhSignInternal failed")

	valid := s.slhVerifyInternal(pk, msg, sig)
	test.CheckOk(valid, "slhVerifyInternal failed", t)
}

func TestInternal(t *testing.T) {
	for _, ins := range instances {
		state, err := ins.ins.newState()
		test.CheckNoErr(t, err, "failed to create a state")
		t.Run(state.name, func(tt *testing.T) { testInternal(tt, state) })
	}
}

func benchmarkInternal(b *testing.B, s *state) {
	skSeed := mustRead(b, s.n)
	skPrf := mustRead(b, s.n)
	pkSeed := mustRead(b, s.n)
	msg := mustRead(b, s.m)
	addRand := mustRead(b, s.n)

	sk, pk := s.slhKeyGenInternal(skSeed, skPrf, pkSeed)
	sig, _ := s.slhSignInternal(sk, msg, addRand)

	b.Run("Keygen", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = s.slhKeyGenInternal(skSeed, skPrf, pkSeed)
		}
	})

	b.Run("Sign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = s.slhSignInternal(sk, msg, addRand)
		}
	})

	b.Run("Verify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = s.slhVerifyInternal(pk, msg, sig)
		}
	})
}

func BenchmarkInternal(b *testing.B) {
	for _, ins := range instances {
		state, err := ins.ins.newState()
		test.CheckNoErr(b, err, "failed to create a state")
		b.Run(state.name, func(bb *testing.B) { benchmarkInternal(bb, state) })
	}
}
