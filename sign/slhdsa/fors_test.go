package slhdsa

import (
	"bytes"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func testFors(t *testing.T, p *params) {
	state := p.newState()

	skSeed := mustRead(t, state.n)
	pkSeed := mustRead(t, state.n)
	msg := mustRead(t, (state.k*state.a+7)/8)

	idxTree := [3]uint32{0, 0, 0}
	idxLeaf := uint32(0)

	addr := p.newAddress()
	addr.SetLayerAddress(uint32(state.d - 1))

	xmssStack := p.newStack(p.hPrime)
	pkRoot := make([]byte, p.n)
	state.xmssNodeIter(&xmssStack, pkRoot, skSeed, idxLeaf, uint32(state.hPrime), pkSeed, addr)

	n0 := make([]byte, state.n)
	state.forsNodeRec(n0, skSeed, idxLeaf, uint32(state.a), pkSeed, addr)

	n1 := make([]byte, state.n)
	forsStack := p.newStack(p.a)
	state.forsNodeIter(&forsStack, n1, skSeed, idxLeaf, uint32(state.a), pkSeed, addr)

	if !bytes.Equal(n0, n1) {
		test.ReportError(t, n0, n1)
	}

	var sig forsSignature
	curSig := cursor(make([]byte, p.forsSigSize()))
	sig.fromBytes(p, &curSig)
	state.forsSign(sig, msg, skSeed, pkSeed, addr)

	pkFors := make([]byte, state.forsPkSize())
	copy(pkFors, state.forsPkFromSig(msg, sig, pkSeed, addr))

	var htSig hyperTreeSignature
	curHtSig := cursor(make([]byte, p.hyperTreeSigSize()))
	htSig.fromBytes(p, &curHtSig)
	state.htSign(htSig, pkFors, skSeed, pkSeed, idxTree, idxLeaf)

	valid := state.htVerify(pkFors, pkSeed, pkRoot, idxTree, idxLeaf, htSig)

	test.CheckOk(valid, "hypertree signature verification failed", t)
}

func benchmarkFors(b *testing.B, p *params) {
	state := p.newState()

	skSeed := mustRead(b, state.n)
	pkSeed := mustRead(b, state.n)
	msg := mustRead(b, (state.k*state.a+7)/8)

	addr := p.newAddress()
	addr.SetLayerAddress(uint32(state.d - 1))

	var sig forsSignature
	curSig := cursor(make([]byte, p.forsSigSize()))
	sig.fromBytes(p, &curSig)
	state.forsSign(sig, msg, skSeed, pkSeed, addr)
	node := make([]byte, state.n)
	forsStack := p.newStack(p.a)

	b.Run("NodeRec", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			state.forsNodeRec(node, skSeed, 0, uint32(state.a), pkSeed, addr)
		}
	})
	b.Run("NodeIter", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			state.forsNodeIter(&forsStack, node, skSeed, 0, uint32(state.a), pkSeed, addr)
		}
	})
	b.Run("Sign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			state.forsSign(sig, msg, skSeed, pkSeed, addr)
		}
	})
	b.Run("PkFromSig", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = state.forsPkFromSig(msg, sig, pkSeed, addr)
		}
	})
}