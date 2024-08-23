package slhdsa

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func testWotsPlus(t *testing.T, p *params) {
	state, err := p.newState()
	test.CheckNoErr(t, err, "failed to create a state")

	skSeed := mustRead(t, state.n)
	pkSeed := mustRead(t, state.n)
	msg := mustRead(t, state.n)

	addr := p.newAddress()
	addr.SetTypeAndClear(addressWotsHash)

	pk0 := make([]byte, p.wotsPkLen())
	state.wotsPkGen(pk0, skSeed, pkSeed, addr)

	sig := make([]byte, p.wotsSigLen())
	state.wotsSign(sig, msg, skSeed, pkSeed, addr)
	test.CheckOk(len(sig) == state.wotsSigLen(), fmt.Sprintf("bad wots+signature length: %v", len(sig)), t)

	pk1 := make([]byte, p.wotsPkLen())
	state.wotsPkFromSig(pk1, sig, msg, pkSeed, addr)

	if !bytes.Equal(pk0, pk1) {
		test.ReportError(t, pk0, pk1, skSeed, pkSeed, msg)
	}
}

func benchmarkWotsPlus(b *testing.B, p *params) {
	state, err := p.newState()
	test.CheckNoErr(b, err, "failed to create a state")

	skSeed := make([]byte, state.n) // mustRead(b, state.n)
	pkSeed := make([]byte, state.n) // mustRead(b, state.n)
	msg := make([]byte, state.n)    // mustRead(b, state.n)

	addr := p.newAddress()
	addr.SetTypeAndClear(addressWotsHash)
	pk := make([]byte, p.wotsPkLen())
	sig := make([]byte, p.wotsSigLen())
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
			state.wotsPkFromSig(pk, sig, msg, pkSeed, addr)
		}
	})
}
