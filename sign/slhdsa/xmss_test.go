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

	skSeed := mustRead(t, state.n)
	pkSeed := mustRead(t, state.n)
	msg := mustRead(t, state.n)

	var addr address
	addr.SetTypeAndClear(addressWotsHash)
	idx := uint32(0)

	root := state.xmssNode(skSeed, idx, uint32(state.hPrime), pkSeed, addr)
	test.CheckOk(len(root) == int(state.n),
		fmt.Sprintf("bad xmss root length: %v", len(root)), t)

	sig := state.xmssSign(msg, skSeed, idx, pkSeed, addr)
	test.CheckOk(len(sig.wotsSig) == int(state.wotsLen()),
		fmt.Sprintf("bad wots+ signature length: %v", len(sig.wotsSig)), t)
	for i := range sig.wotsSig {
		test.CheckOk(
			len(sig.wotsSig[i]) == int(state.n),
			fmt.Sprintf("bad length of wots+ signature's %v-th element: %v", i, len(sig.wotsSig[i])), t)
	}

	test.CheckOk(len(sig.authPath) == int(state.hPrime),
		fmt.Sprintf("bad authPath length: %v", len(sig.authPath)), t)
	for i := range sig.authPath {
		test.CheckOk(
			len(sig.authPath[i]) == int(state.n),
			fmt.Sprintf("bad length of authPath's %v-th element: %v", i, len(sig.authPath[i])), t)
	}

	node := state.xmssPkFromSig(msg, pkSeed, sig, idx, addr)
	test.CheckOk(len(node) == int(state.n), fmt.Sprintf("bad node length: %v", len(node)), t)

	if !bytes.Equal(root, node) {
		test.ReportError(t, root, node, skSeed, pkSeed, msg)
	}
}

func benchmarkXmss(b *testing.B, p *params) {
	state, err := p.newState()
	test.CheckNoErr(b, err, "failed to create a state")

	skSeed := mustRead(b, state.n)
	pkSeed := mustRead(b, state.n)
	msg := mustRead(b, state.n)

	var addr address
	addr.SetTypeAndClear(addressWotsHash)
	idx := uint32(0)
	sig := state.xmssSign(msg, skSeed, idx, pkSeed, addr)

	b.Run("Sign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = state.xmssSign(msg, skSeed, idx, pkSeed, addr)
		}
	})
	b.Run("PkFromSig", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = state.xmssPkFromSig(msg, pkSeed, sig, idx, addr)
		}
	})
}
