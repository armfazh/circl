package slhdsa

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func testXmss(t *testing.T, p *params) {
	state, err := p.newState()
	test.CheckNoErr(t, err, "failed to create a state")

	skSeed := make([]byte, state.n) // mustRead(b, state.n)
	pkSeed := make([]byte, state.n) // mustRead(b, state.n)
	msg := make([]byte, state.n)    // mustRead(b, state.n)

	addr := p.newAddress()
	addr.SetTypeAndClear(addressWotsHash)
	idx := uint32(0)

	ad0 := *addr
	ad1 := *addr

	rootRec := state.xmssNodeRec(skSeed, idx, uint32(p.hPrime), pkSeed, &ad0)
	test.CheckOk(len(rootRec) == state.n, fmt.Sprintf("bad xmss rootRec length: %v", len(rootRec)), t)

	xs := p.newXmssState(uint32(p.hPrime))
	rootIter := make([]byte, p.n)
	state.xmssNodeIter(&xs, rootIter, skSeed, idx, uint32(p.hPrime), pkSeed, &ad1)
	test.CheckOk(len(rootIter) == state.n, fmt.Sprintf("bad xmss rootIter length: %v", len(rootIter)), t)

	if !bytes.Equal(rootRec, rootIter) {
		test.ReportError(t, rootRec, rootIter, skSeed, pkSeed, msg)
	}

	var sig xmssSignature
	sig.wotsSig = make([]byte, p.wotsSigLen())
	sig.authPath = make([]byte, p.xmssAuthPathLen())
	state.xmssSign(&xs, sig, msg, skSeed, idx, pkSeed, addr)
	test.CheckOk(len(sig.wotsSig) == state.wotsSigLen(), fmt.Sprintf("bad wots+signature length: %v", len(sig.wotsSig)), t)
	test.CheckOk(len(sig.authPath) == state.hPrime*state.n, fmt.Sprintf("bad authPath length: %v", len(sig.authPath)), t)
	test.CheckOk(len(sig.wotsSig)+len(sig.authPath) == state.xmssSigLen(),
		fmt.Sprintf("bad xmss signature length: %v", len(sig.wotsSig)+len(sig.authPath)), t)

	node := state.xmssPkFromSig(msg, pkSeed, sig, idx, addr)

	if !bytes.Equal(rootRec, node) {
		test.ReportError(t, rootRec, node, skSeed, pkSeed, msg)
	}
}

func benchmarkXmss(b *testing.B, p *params) {
	state, err := p.newState()
	test.CheckNoErr(b, err, "failed to create a state")

	skSeed := make([]byte, state.n) // mustRead(b, state.n)
	pkSeed := make([]byte, state.n) // mustRead(b, state.n)
	msg := make([]byte, state.n)    // mustRead(b, state.n)

	addr := p.newAddress()
	addr.SetTypeAndClear(addressWotsHash)
	idx := uint32(0)
	xs := state.newXmssState(uint32(state.hPrime))
	var sig xmssSignature
	sig.wotsSig = make([]byte, p.wotsSigLen())
	sig.authPath = make([]byte, p.xmssAuthPathLen())

	state.xmssSign(&xs, sig, msg, skSeed, idx, pkSeed, addr)
	node := make([]byte, p.n)

	b.Run("NodeRec", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = state.xmssNodeRec(skSeed, idx, uint32(p.hPrime), pkSeed, addr)
		}
	})
	b.Run("NodeIter", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			state.xmssNodeIter(&xs, node, skSeed, idx, uint32(p.hPrime), pkSeed, addr)
		}
	})
	b.Run("Sign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			state.xmssSign(&xs, sig, msg, skSeed, idx, pkSeed, addr)
		}
	})
	b.Run("PkFromSig", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = state.xmssPkFromSig(msg, pkSeed, sig, idx, addr)
		}
	})
}
