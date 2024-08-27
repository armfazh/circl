package slhdsa

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func testXmss(t *testing.T, p *params) {
	state := p.newState()

	skSeed := make([]byte, state.n) // mustRead(b, state.n)
	pkSeed := make([]byte, state.n) // mustRead(b, state.n)
	msg := make([]byte, state.n)    // mustRead(b, state.n)

	addr := p.newAddress()
	addr.SetTypeAndClear(addressWotsHash)
	idx := uint32(0)

	rootRec := state.xmssNodeRec(skSeed, idx, uint32(p.hPrime), pkSeed, addr)
	test.CheckOk(len(rootRec) == state.n, fmt.Sprintf("bad xmss rootRec length: %v", len(rootRec)), t)

	stack := p.newStack(p.hPrime)
	rootIter := make([]byte, p.n)
	state.xmssNodeIter(&stack, rootIter, skSeed, idx, uint32(p.hPrime), pkSeed, addr)

	if !bytes.Equal(rootRec, rootIter) {
		test.ReportError(t, rootRec, rootIter, skSeed, pkSeed, msg)
	}

	var sig xmssSignature
	curSig := cursor(make([]byte, p.xmssSigSize()))
	sig.fromBytes(p, &curSig)
	state.xmssSign(&stack, sig, msg, skSeed, idx, pkSeed, addr)

	node := state.xmssPkFromSig(msg, pkSeed, sig, idx, addr)

	if !bytes.Equal(rootRec, node) {
		test.ReportError(t, rootRec, node, skSeed, pkSeed, msg)
	}
}

func benchmarkXmss(b *testing.B, p *params) {
	state := p.newState()

	skSeed := mustRead(b, state.n)
	pkSeed := mustRead(b, state.n)
	msg := mustRead(b, state.n)

	addr := p.newAddress()
	addr.SetTypeAndClear(addressWotsHash)
	idx := uint32(0)
	stack := state.newStack(state.hPrime)

	var sig xmssSignature
	curSig := cursor(make([]byte, p.xmssSigSize()))
	sig.fromBytes(p, &curSig)
	state.xmssSign(&stack, sig, msg, skSeed, idx, pkSeed, addr)
	node := make([]byte, p.n)

	b.Run("NodeRec", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = state.xmssNodeRec(skSeed, idx, uint32(p.hPrime), pkSeed, addr)
		}
	})
	b.Run("NodeIter", func(b *testing.B) {
		s := state.newStack(state.hPrime)
		for i := 0; i < b.N; i++ {
			state.xmssNodeIter(&s, node, skSeed, idx, uint32(p.hPrime), pkSeed, addr)
		}
	})
	b.Run("Sign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			state.xmssSign(&stack, sig, msg, skSeed, idx, pkSeed, addr)
		}
	})
	b.Run("PkFromSig", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = state.xmssPkFromSig(msg, pkSeed, sig, idx, addr)
		}
	})
}
