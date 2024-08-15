package slhdsa

import (
	"fmt"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func testFors(t *testing.T, p *params) {
	state, err := p.newState()
	test.CheckNoErr(t, err, "failed to create a state")

	skSeed := mustRead(t, state.n)
	pkSeed := mustRead(t, state.n)
	msg := mustRead(t, (state.k*state.a+7)/8)

	idxTree := [3]uint32{0, 0, 0}
	idxLeaf := uint32(0)

	var addr address
	addr.SetLayerAddress(uint32(state.d - 1))
	pkRoot := state.xmssNode(skSeed, idxLeaf, uint32(state.hPrime), pkSeed, addr)
	test.CheckOk(len(pkRoot) == int(state.n),
		fmt.Sprintf("bad xmss root length: %v", len(pkRoot)), t)

	sig := state.forsSign(msg, skSeed, pkSeed, addr)
	test.CheckOk(len(sig) == int(state.k),
		fmt.Sprintf("bad hypertree signature length: %v", len(sig)), t)

	pkFors := state.forsPkFromSig(msg, sig, pkSeed, addr)
	htSig := state.htSign(pkFors, skSeed, pkSeed, idxTree, idxLeaf)
	valid := state.htVerify(pkFors, pkSeed, pkRoot, idxTree, idxLeaf, htSig)

	test.CheckOk(valid, "hypertree signature verification failed", t)
}

func benchmarkFors(b *testing.B, p *params) {
	state, err := p.newState()
	test.CheckNoErr(b, err, "failed to create a state")

	skSeed := mustRead(b, state.n)
	pkSeed := mustRead(b, state.n)
	msg := mustRead(b, (state.k*state.a+7)/8)

	var addr address
	addr.SetLayerAddress(uint32(state.d - 1))
	sig := state.forsSign(msg, skSeed, pkSeed, addr)

	b.Run("Sign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = state.forsSign(msg, skSeed, pkSeed, addr)
		}
	})
	b.Run("Verify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = state.forsPkFromSig(msg, sig, pkSeed, addr)
		}
	})
}
