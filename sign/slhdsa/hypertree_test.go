package slhdsa

import (
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func testHyperTree(t *testing.T, p *params) {
	state := p.newState()

	skSeed := mustRead(t, state.n)
	pkSeed := mustRead(t, state.n)
	msg := mustRead(t, state.n)

	idxTree := [3]uint32{0, 0, 0}
	idxLeaf := uint32(0)

	addr := p.newAddress()
	addr.SetLayerAddress(uint32(state.d - 1))
	stack := p.newStack(p.hPrime)
	pkRoot := make([]byte, p.n)
	state.xmssNodeIter(&stack, pkRoot, skSeed, idxLeaf, uint32(state.hPrime), pkSeed, addr)

	var sig hyperTreeSignature
	curSig := cursor(make([]byte, p.hyperTreeSigSize()))
	sig.fromBytes(p, &curSig)
	state.htSign(sig, msg, skSeed, pkSeed, idxTree, idxLeaf)

	valid := state.htVerify(msg, pkSeed, pkRoot, idxTree, idxLeaf, sig)
	test.CheckOk(valid, "hypertree signature verification failed", t)
}

func benchmarkHyperTree(b *testing.B, p *params) {
	state := p.newState()

	skSeed := mustRead(b, state.n)
	pkSeed := mustRead(b, state.n)
	pkRoot := mustRead(b, state.n)
	msg := mustRead(b, state.n)

	idxTree := [3]uint32{0, 0, 0}
	idxLeaf := uint32(0)

	var sig hyperTreeSignature
	curSig := cursor(make([]byte, p.hyperTreeSigSize()))
	sig.fromBytes(p, &curSig)
	state.htSign(sig, msg, skSeed, pkSeed, idxTree, idxLeaf)

	b.Run("Sign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			state.htSign(sig, msg, skSeed, pkSeed, idxTree, idxLeaf)
		}
	})
	b.Run("Verify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = state.htVerify(msg, pkSeed, pkRoot, idxTree, idxLeaf, sig)
		}
	})
}
