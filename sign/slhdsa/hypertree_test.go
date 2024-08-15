package slhdsa

import (
	"fmt"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func testHyperTree(t *testing.T, s *state) {
	skSeed := mustRead(t, s.n)
	pkSeed := mustRead(t, s.n)
	msg := mustRead(t, s.n)

	idxTree := [3]uint32{0, 0, 0}
	idxLeaf := uint32(0)

	var addr address
	addr.SetLayerAddress(uint32(s.d - 1))
	pkRoot := s.xmssNode(skSeed, idxLeaf, uint32(s.hPrime), pkSeed, addr)

	test.CheckOk(len(pkRoot) == int(s.n),
		fmt.Sprintf("bad xmss root length: %v", len(pkRoot)), t)

	sig := s.htSign(msg, skSeed, pkSeed, idxTree, idxLeaf)
	test.CheckOk(len(sig) == int(s.d),
		fmt.Sprintf("bad hypertree signature length: %v", len(sig)), t)

	valid := s.htVerify(msg, pkSeed, pkRoot, idxTree, idxLeaf, sig)
	test.CheckOk(valid, "hypertree signature verification failed", t)
}

func TestHyperTree(t *testing.T) {
	for _, ins := range instances {
		state, err := ins.ins.newState()
		test.CheckNoErr(t, err, "failed to create a state")
		t.Run(state.name, func(tt *testing.T) { testHyperTree(tt, state) })
	}
}

func benchmarkHyperTree(b *testing.B, s *state) {
	skSeed := mustRead(b, s.n)
	pkSeed := mustRead(b, s.n)
	pkRoot := mustRead(b, s.n)
	msg := mustRead(b, s.n)

	idxTree := [3]uint32{0, 0, 0}
	idxLeaf := uint32(0)

	sig := s.htSign(msg, skSeed, pkSeed, idxTree, idxLeaf)

	b.Run("Sign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = s.htSign(msg, skSeed, pkSeed, idxTree, idxLeaf)
		}
	})

	b.Run("Verify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = s.htVerify(msg, pkSeed, pkRoot, idxTree, idxLeaf, sig)
		}
	})
}

func BenchmarkHyperTree(b *testing.B) {
	for _, ins := range instances {
		state, err := ins.ins.newState()
		test.CheckNoErr(b, err, "failed to create a state")
		b.Run(state.name, func(bb *testing.B) { benchmarkHyperTree(bb, state) })
	}
}
