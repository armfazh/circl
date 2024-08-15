package slhdsa

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func testXmss(t *testing.T, s *state) {
	skSeed := mustRead(t, s.n)
	pkSeed := mustRead(t, s.n)
	msg := mustRead(t, s.n)

	var addr address
	addr.SetTypeAndClear(addressWotsHash)
	idx := uint32(0)

	root := s.xmssNode(skSeed, idx, uint32(s.hPrime), pkSeed, addr)
	test.CheckOk(len(root) == int(s.n),
		fmt.Sprintf("bad xmss root length: %v", len(root)), t)

	sig := s.xmssSign(msg, skSeed, idx, pkSeed, addr)
	test.CheckOk(len(sig.wotsSig) == int(s.wotsLen()),
		fmt.Sprintf("bad wots+ signature length: %v", len(sig.wotsSig)), t)
	for i := range sig.wotsSig {
		test.CheckOk(
			len(sig.wotsSig[i]) == int(s.n),
			fmt.Sprintf("bad length of wots+ signature's %v-th element: %v", i, len(sig.wotsSig[i])), t)
	}

	test.CheckOk(len(sig.authPath) == int(s.hPrime),
		fmt.Sprintf("bad authPath length: %v", len(sig.authPath)), t)
	for i := range sig.authPath {
		test.CheckOk(
			len(sig.authPath[i]) == int(s.n),
			fmt.Sprintf("bad length of authPath's %v-th element: %v", i, len(sig.authPath[i])), t)
	}

	node := s.xmssPkFromSig(msg, pkSeed, sig, idx, addr)
	test.CheckOk(len(node) == int(s.n), fmt.Sprintf("bad node length: %v", len(node)), t)

	if !bytes.Equal(root, node) {
		test.ReportError(t, root, node, skSeed, pkSeed, msg)
	}
}

func TestXmss(t *testing.T) {
	for _, ins := range instances {
		state, err := ins.ins.newState()
		test.CheckNoErr(t, err, "failed to create a state")
		t.Run(state.name, func(tt *testing.T) { testXmss(tt, state) })
	}
}

func benchmarkXmss(b *testing.B, s *state) {
	skSeed := mustRead(b, s.n)
	pkSeed := mustRead(b, s.n)
	msg := mustRead(b, s.n)

	var addr address
	addr.SetTypeAndClear(addressWotsHash)
	idx := uint32(0)
	sig := s.xmssSign(msg, skSeed, idx, pkSeed, addr)

	b.Run("Sign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = s.xmssSign(msg, skSeed, idx, pkSeed, addr)
		}
	})

	b.Run("PkFromSig", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = s.xmssPkFromSig(msg, pkSeed, sig, idx, addr)
		}
	})
}

func BenchmarkXmss(b *testing.B) {
	for _, ins := range instances {
		state, err := ins.ins.newState()
		test.CheckNoErr(b, err, "failed to create a state")
		b.Run(state.name, func(bb *testing.B) { benchmarkXmss(bb, state) })
	}
}
