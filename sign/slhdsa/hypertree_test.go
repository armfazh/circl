package slhdsa

import (
	"fmt"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func testHyperTree(t *testing.T, p *params) {
	state, err := p.newState()
	test.CheckNoErr(t, err, "failed to create a state")

	skSeed := mustRead(t, state.n)
	pkSeed := mustRead(t, state.n)
	msg := mustRead(t, state.n)

	idxTree := [3]uint32{0, 0, 0}
	idxLeaf := uint32(0)

	addr := p.newAddress()
	addr.SetLayerAddress(uint32(state.d - 1))
	pkRoot := state.xmssNode(skSeed, idxLeaf, uint32(state.hPrime), pkSeed, addr)

	test.CheckOk(len(pkRoot) == state.n, fmt.Sprintf("bad xmss root length: %v", len(pkRoot)), t)

	sig := state.htSign(msg, skSeed, pkSeed, idxTree, idxLeaf)
	test.CheckOk(len(sig) == state.d, fmt.Sprintf("bad hypertree signature length: %v", len(sig)), t)

	valid := state.htVerify(msg, pkSeed, pkRoot, idxTree, idxLeaf, sig)
	test.CheckOk(valid, "hypertree signature verification failed", t)
}

func benchmarkHyperTree(b *testing.B, p *params) {
	state, err := p.newState()
	test.CheckNoErr(b, err, "failed to create a state")

	skSeed := mustRead(b, state.n)
	pkSeed := mustRead(b, state.n)
	pkRoot := mustRead(b, state.n)
	msg := mustRead(b, state.n)

	idxTree := [3]uint32{0, 0, 0}
	idxLeaf := uint32(0)

	sig := state.htSign(msg, skSeed, pkSeed, idxTree, idxLeaf)

	b.Run("Sign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = state.htSign(msg, skSeed, pkSeed, idxTree, idxLeaf)
		}
	})
	b.Run("Verify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = state.htVerify(msg, pkSeed, pkRoot, idxTree, idxLeaf, sig)
		}
	})
}
