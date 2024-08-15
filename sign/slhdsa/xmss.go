package slhdsa

import "golang.org/x/crypto/cryptobyte"

type (
	xmssPublicKey []byte // n bytes
	xmssSignature struct {
		wotsSig  wotsSignature // len*n bytes
		authPath [][]byte      // h*n bytes
	}
)

func (xs *xmssSignature) Marshal(b *cryptobyte.Builder) (err error) {
	b.AddValue(&xs.wotsSig)
	for i := range xs.authPath {
		b.AddBytes(xs.authPath[i])
	}
	return
}

func (xs *xmssSignature) Unmarshal(p *params, str *cryptobyte.String) bool {
	if !xs.wotsSig.Unmarshal(p, str) {
		return false
	}

	xs.authPath = make([][]byte, p.hPrime)
	buf := make([]byte, p.n*p.hPrime)
	for i := uint(0); i < p.hPrime; i++ {
		xs.authPath[i] = buf[:p.n]
		if !str.CopyBytes(xs.authPath[i]) {
			return false
		}
		buf = buf[p.n:]
	}

	return true
}

func (s *state) xmssNode(skSeed []byte, i, z uint32, pkSeed []byte, addr address) (node []byte) {
	return s.xmssNodeRec(skSeed, i, z, pkSeed, addr)
}

func (s *state) xmssNodeRec(skSeed []byte, i, z uint32, pkSeed []byte, addr address) (node []byte) {
	if !(z <= uint32(s.hPrime) && i < (1<<(uint32(s.hPrime)-z))) {
		panic(ErrNode)
	}

	if z == 0 {
		addr.SetTypeAndClear(addressWotsHash)
		addr.SetKeyPairAddress(i)
		node = s.wotsPkGen(skSeed, pkSeed, addr)
	} else {
		lnode := s.xmssNodeRec(skSeed, 2*i, z-1, pkSeed, addr)
		rnode := s.xmssNodeRec(skSeed, 2*i+1, z-1, pkSeed, addr)
		addr.SetTypeAndClear(addressTree)
		addr.SetTreeHeight(z)
		addr.SetTreeIndex(i)
		node = s.hasher.H(pkSeed, addr, [2][]byte{lnode, rnode})
	}

	return
}

func (s *state) xmssSign(msg, skSeed []byte, idx uint32, pkSeed []byte, addr address) (sig xmssSignature) {
	sig.authPath = make([][]byte, s.hPrime)
	for j := uint32(0); j < uint32(s.hPrime); j++ {
		k := (idx >> j) ^ 1
		sig.authPath[j] = s.xmssNode(skSeed, k, j, pkSeed, addr)
	}

	addr.SetTypeAndClear(addressWotsHash)
	addr.SetKeyPairAddress(idx)
	sig.wotsSig = s.wotsSign(msg, skSeed, pkSeed, addr)

	return
}

func (s *state) xmssPkFromSig(msg, pkSeed []byte, sig xmssSignature, idx uint32, addr address) (pk xmssPublicKey) {
	addr.SetTypeAndClear(addressWotsHash)
	addr.SetKeyPairAddress(idx)
	pk = xmssPublicKey(s.wotsPkFromSig(sig.wotsSig, msg, pkSeed, addr))

	addr.SetTypeAndClear(addressTree)
	addr.SetTreeIndex(idx)

	for k := uint(0); k < s.hPrime; k++ {
		addr.SetTreeHeight(uint32(k + 1))
		if (idx>>k)&0x1 == 0 {
			addr.SetTreeIndex(addr.GetTreeIndex() >> 1)
			pk = s.hasher.H(pkSeed, addr, [2][]byte{pk, sig.authPath[k]})
		} else {
			addr.SetTreeIndex((addr.GetTreeIndex() - 1) >> 1)
			pk = s.hasher.H(pkSeed, addr, [2][]byte{sig.authPath[k], pk})
		}
	}

	return
}
