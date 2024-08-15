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

	var addr address
	addr.SetTypeAndClear(addressWotsHash)

	pk0 := state.wotsPkGen(skSeed, pkSeed, addr)
	test.CheckOk(len(pk0) == int(state.n),
		fmt.Sprintf("bad wots+ public key length: %v", len(pk0)), t)

	sig := state.wotsSign(msg, skSeed, pkSeed, addr)
	test.CheckOk(len(sig) == int(state.wotsLen()),
		fmt.Sprintf("bad wots+signature length: %v", len(sig)), t)
	for i := range sig {
		test.CheckOk(
			len(sig[i]) == int(state.n),
			fmt.Sprintf("bad length of wots+ signature's %v-th element: %v", i, len(sig[i])), t)
	}

	pk1 := state.wotsPkFromSig(sig, msg, pkSeed, addr)
	test.CheckOk(len(pk1) == int(state.n), fmt.Sprintf("bad wots+ public key length: %v", len(pk1)), t)

	if !bytes.Equal(pk0, pk1) {
		test.ReportError(t, pk0, pk1, skSeed, pkSeed, msg)
	}
}

func benchmarkWotsPlus(b *testing.B, p *params) {
	state, err := p.newState()
	test.CheckNoErr(b, err, "failed to create a state")

	skSeed := mustRead(b, state.n)
	pkSeed := mustRead(b, state.n)
	msg := mustRead(b, state.n)

	var addr address
	addr.SetTypeAndClear(addressWotsHash)
	sig := state.wotsSign(msg, skSeed, pkSeed, addr)

	b.Run("PkGen", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = state.wotsPkGen(skSeed, pkSeed, addr)
		}
	})
	b.Run("Sign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = state.wotsSign(msg, skSeed, pkSeed, addr)
		}
	})
	b.Run("PkFromSig", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = state.wotsPkFromSig(sig, msg, pkSeed, addr)
		}
	})
}
