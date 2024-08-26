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

	addr := p.newAddress()
	addr.SetLayerAddress(uint32(state.d - 1))
	xs := p.newXmssState(uint32(p.hPrime))
	pkRoot := make([]byte, p.n)
	state.xmssNode(&xs, pkRoot, skSeed, idxLeaf, uint32(state.hPrime), pkSeed, addr)
	test.CheckOk(len(pkRoot) == state.n, fmt.Sprintf("bad xmss root length: %v", len(pkRoot)), t)

	sig := state.forsSign(msg, skSeed, pkSeed, addr)
	test.CheckOk(len(sig) == state.k, fmt.Sprintf("bad hypertree signature length: %v", len(sig)), t)

	pkFors := make([]byte, p.forsPkLen())
	state.forsPkFromSig(pkFors, msg, sig, pkSeed, addr)
	var htSig hyperTreeSignature = make([]xmssSignature, p.d)
	state.htSign(htSig, pkFors, skSeed, pkSeed, idxTree, idxLeaf)
	valid := state.htVerify(pkFors, pkSeed, pkRoot, idxTree, idxLeaf, htSig)

	test.CheckOk(valid, "hypertree signature verification failed", t)
}

func benchmarkFors(b *testing.B, p *params) {
	state, err := p.newState()
	test.CheckNoErr(b, err, "failed to create a state")

	skSeed := mustRead(b, state.n)
	pkSeed := mustRead(b, state.n)
	msg := mustRead(b, (state.k*state.a+7)/8)

	addr := p.newAddress()
	addr.SetLayerAddress(uint32(state.d - 1))
	pkFors := make([]byte, p.forsPkLen())
	sig := state.forsSign(msg, skSeed, pkSeed, addr)

	b.Run("Sign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = state.forsSign(msg, skSeed, pkSeed, addr)
		}
	})
	b.Run("PkFromSig", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			state.forsPkFromSig(pkFors, msg, sig, pkSeed, addr)
		}
	})
}
