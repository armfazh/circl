package slhdsa

import (
	"bytes"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func testWotsPlus(t *testing.T, p *params) {
	state := p.newState()

	skSeed := mustRead(t, state.n)
	pkSeed := mustRead(t, state.n)
	msg := mustRead(t, state.n)

	addr := p.newAddress()
	addr.SetTypeAndClear(addressWotsHash)

	pk0 := make([]byte, p.wotsPkSize())
	state.wotsPkGen(pk0, skSeed, pkSeed, addr)

	var sig wotsSignature
	curSig := cursor(make([]byte, p.wotsSigSize()))
	sig.fromBytes(p, &curSig)
	state.wotsSign(sig, msg, skSeed, pkSeed, addr)

	pk1 := state.wotsPkFromSig(sig, msg, pkSeed, addr)

	if !bytes.Equal(pk0, pk1) {
		test.ReportError(t, pk0, pk1, skSeed, pkSeed, msg)
	}
}

func benchmarkWotsPlus(b *testing.B, p *params) {
	state := p.newState()

	skSeed := mustRead(b, state.n)
	pkSeed := mustRead(b, state.n)
	msg := mustRead(b, state.n)

	addr := p.newAddress()
	addr.SetTypeAndClear(addressWotsHash)

	var sig wotsSignature
	curSig := cursor(make([]byte, p.wotsSigSize()))
	sig.fromBytes(p, &curSig)
	pk := make([]byte, p.wotsPkSize())
	state.wotsSign(sig, msg, skSeed, pkSeed, addr)

	b.Run("PkGen", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			state.wotsPkGen(pk, skSeed, pkSeed, addr)
		}
	})
	b.Run("Sign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			state.wotsSign(sig, msg, skSeed, pkSeed, addr)
		}
	})
	b.Run("PkFromSig", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = state.wotsPkFromSig(sig, msg, pkSeed, addr)
		}
	})
}
