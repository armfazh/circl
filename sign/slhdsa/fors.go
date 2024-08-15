package slhdsa

import (
	"math/big"

	"golang.org/x/crypto/cryptobyte"
)

type (
	forsPublicKey  []byte
	forsPrivateKey []byte
	forsSignature  []forsSigPair
	forsSigPair    struct {
		sk   forsPrivateKey
		auth [][]byte
	}
)

func (fsp *forsSigPair) Marshal(b *cryptobyte.Builder) (err error) {
	b.AddBytes(fsp.sk)
	for i := range fsp.auth {
		b.AddBytes(fsp.auth[i])
	}

	return
}

func (fs *forsSignature) Marshal(b *cryptobyte.Builder) (err error) {
	for i := range *fs {
		b.AddValue(&(*fs)[i])
	}

	return
}

func (fsp *forsSigPair) Unmarshal(p *params, str *cryptobyte.String) bool {
	fsp.sk = make([]byte, p.n)
	if !str.CopyBytes(fsp.sk) {
		return false
	}

	fsp.auth = make([][]byte, p.a)
	buf := make([]byte, p.a*p.n)
	for i := uint(0); i < p.a; i++ {
		fsp.auth[i] = buf[:p.n]
		if !str.CopyBytes(fsp.auth[i]) {
			return false
		}
		buf = buf[p.n:]
	}

	return true
}

func (fs *forsSignature) Unmarshal(p *params, str *cryptobyte.String) bool {
	*fs = make([]forsSigPair, p.k)
	for i := uint(0); i < p.k; i++ {
		if !(*fs)[i].Unmarshal(p, str) {
			return false
		}
	}

	return true
}

func (s *state) forsSkGen(skSeed, pkSeed []byte, addr address, idx uint32) (sk forsPrivateKey) {
	skAddr := addr
	skAddr.SetTypeAndClear(addressForsPrf)
	skAddr.SetKeyPairAddress(addr.GetKeyPairAddress())
	skAddr.SetTreeIndex(idx)
	return s.hasher.PRF(pkSeed, skSeed, skAddr)
}

func (s *state) forsNode(skSeed []byte, i, z uint32, pkSeed []byte, addr address) (node []byte) {
	return s.forsNodeRec(skSeed, i, z, pkSeed, addr)
}

func (s *state) forsNodeRec(skSeed []byte, i, z uint32, pkSeed []byte, addr address) (node []byte) {
	if !(z <= uint32(s.a) && i < uint32(s.k)*(1<<(uint32(s.a)-z))) {
		panic(ErrNode)
	}

	if z == 0 {
		sk := s.forsSkGen(skSeed, pkSeed, addr, i)
		addr.SetTreeHeight(0)
		addr.SetTreeIndex(i)
		node = s.hasher.F(pkSeed, addr, sk)
	} else {
		lnode := s.forsNodeRec(skSeed, 2*i, z-1, pkSeed, addr)
		rnode := s.forsNodeRec(skSeed, 2*i+1, z-1, pkSeed, addr)
		addr.SetTreeHeight(z)
		addr.SetTreeIndex(i)
		node = s.hasher.H(pkSeed, addr, [2][]byte{lnode, rnode})
	}

	return
}

func (p *params) getIndices(msgDigest []byte) (indices []uint32) {
	if len(msgDigest) != int((p.k*p.a+7)/8) {
		panic(ErrMsgDigest)
	}

	indices = make([]uint32, p.k)

	m := new(big.Int).SetBytes(msgDigest)
	m.Rsh(m, 8*uint(len(msgDigest))-p.k*p.a) // removes unused LSB bits

	twoA := new(big.Int).SetUint64(1)
	twoA.Lsh(twoA, p.a)

	for k := uint(0); k < p.k; k++ {
		indices[p.k-1-k] = uint32(new(big.Int).Mod(m, twoA).Uint64())
		m.Rsh(m, p.a)
	}

	return
}

func (s *state) forsSign(msgDigest []byte, skSeed, pkSeed []byte, addr address) (sig forsSignature) {
	indices := s.getIndices(msgDigest)
	sig = make([]forsSigPair, s.k)
	for i := uint32(0); i < uint32(s.k); i++ {
		sig[i].sk = s.forsSkGen(skSeed, pkSeed, addr, (i<<uint32(s.a))+indices[i])
		sig[i].auth = make([][]byte, s.a)
		for j := uint32(0); j < uint32(s.a); j++ {
			sOffset := (indices[i] >> j) ^ 1
			sig[i].auth[j] = s.forsNode(skSeed, (i<<(uint32(s.a)-j))+sOffset, j, pkSeed, addr)
		}
	}

	return
}

func (s *state) forsPkFromSig(msgDigest []byte, sig forsSignature, pkSeed []byte, addr address) forsPublicKey {
	indices := s.getIndices(msgDigest)
	root := make([][]byte, s.k)
	for i := uint32(0); i < uint32(s.k); i++ {
		addr.SetTreeHeight(0)
		addr.SetTreeIndex((i << s.a) + indices[i])
		node := s.hasher.F(pkSeed, addr, sig[i].sk)

		for j := uint32(0); j < uint32(s.a); j++ {
			addr.SetTreeHeight(j + 1)
			if (indices[i]>>j)&0x1 == 0 {
				addr.SetTreeIndex(addr.GetTreeIndex() / 2)
				node = s.hasher.H(pkSeed, addr, [2][]byte{node, sig[i].auth[j]})
			} else {
				addr.SetTreeIndex((addr.GetTreeIndex() - 1) / 2)
				node = s.hasher.H(pkSeed, addr, [2][]byte{sig[i].auth[j], node})
			}
		}
		root[i] = node
	}

	forsPkAddr := addr
	forsPkAddr.SetTypeAndClear(addressForsRoots)
	forsPkAddr.SetKeyPairAddress(addr.GetKeyPairAddress())
	return s.hasher.T(pkSeed, forsPkAddr, root)
}
