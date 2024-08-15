package slhdsa

import (
	"fmt"
	"testing"

	"github.com/cloudflare/circl/internal/test"
)

func testFors(t *testing.T, s *state) {
	skSeed := mustRead(t, s.n)
	pkSeed := mustRead(t, s.n)
	msg := mustRead(t, (s.k*s.a+7)/8)

	idxTree := [3]uint32{0, 0, 0}
	idxLeaf := uint32(0)

	var addr address
	addr.SetLayerAddress(uint32(s.d - 1))
	pkRoot := s.xmssNode(skSeed, idxLeaf, uint32(s.hPrime), pkSeed, addr)
	test.CheckOk(len(pkRoot) == int(s.n),
		fmt.Sprintf("bad xmss root length: %v", len(pkRoot)), t)

	sig := s.forsSign(msg, skSeed, pkSeed, addr)
	test.CheckOk(len(sig) == int(s.k),
		fmt.Sprintf("bad hypertree signature length: %v", len(sig)), t)

	pkFors := s.forsPkFromSig(msg, sig, pkSeed, addr)
	htSig := s.htSign(pkFors, skSeed, pkSeed, idxTree, idxLeaf)
	valid := s.htVerify(pkFors, pkSeed, pkRoot, idxTree, idxLeaf, htSig)

	test.CheckOk(valid, "hypertree signature verification failed", t)
}

func TestFors(t *testing.T) {
	for _, ins := range instances {
		state, err := ins.ins.newState()
		test.CheckNoErr(t, err, "failed to create a state")
		t.Run(state.name, func(tt *testing.T) { testFors(tt, state) })
	}
}

func benchmarkFors(b *testing.B, s *state) {
	skSeed := mustRead(b, s.n)
	pkSeed := mustRead(b, s.n)
	msg := mustRead(b, (s.k*s.a+7)/8)

	var addr address
	addr.SetLayerAddress(uint32(s.d - 1))
	sig := s.forsSign(msg, skSeed, pkSeed, addr)

	b.Run("Sign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = s.forsSign(msg, skSeed, pkSeed, addr)
		}
	})

	b.Run("Verify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = s.forsPkFromSig(msg, sig, pkSeed, addr)
		}
	})
}

func BenchmarkFors(b *testing.B) {
	for _, ins := range instances {
		state, err := ins.ins.newState()
		test.CheckNoErr(b, err, "failed to create a state")
		b.Run(state.name, func(bb *testing.B) { benchmarkFors(bb, state) })
	}
}
