package slhdsa

import (
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func testInternal(t *testing.T, p *params) {
	state := p.newState()

	skSeed := mustRead(t, state.n)
	skPrf := mustRead(t, state.n)
	pkSeed := mustRead(t, state.n)
	msg := mustRead(t, state.m)
	addRand := mustRead(t, state.n)

	sk, pk := state.slhKeyGenInternal(skSeed, skPrf, pkSeed)

	sig, err := state.slhSignInternal(sk, msg, addRand)
	test.CheckNoErr(t, err, "slhSignInternal failed")

	valid := state.slhVerifyInternal(pk, msg, sig)
	test.CheckOk(valid, "slhVerifyInternal failed", t)
}

func benchmarkInternal(b *testing.B, p *params) {
	state := p.newState()

	skSeed := mustRead(b, state.n)
	skPrf := mustRead(b, state.n)
	pkSeed := mustRead(b, state.n)
	msg := mustRead(b, state.m)
	addRand := mustRead(b, state.n)

	sk, pk := state.slhKeyGenInternal(skSeed, skPrf, pkSeed)
	sig, err := state.slhSignInternal(sk, msg, addRand)
	test.CheckNoErr(b, err, "slhSignInternal failed")

	b.Run("Keygen", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = state.slhKeyGenInternal(skSeed, skPrf, pkSeed)
		}
	})
	b.Run("Sign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = state.slhSignInternal(sk, msg, addRand)
		}
	})
	b.Run("Verify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = state.slhVerifyInternal(pk, msg, sig)
		}
	})
}
