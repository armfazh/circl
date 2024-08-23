package slhdsa

import (
	"math/big"

	"golang.org/x/crypto/cryptobyte"
)

func (s *state) slhKeyGenInternal(skSeed, skPrf, pkSeed []byte) (sk *PrivateKey, pk *PublicKey) {
	addr := s.newAddress()
	addr.SetLayerAddress(uint32(s.d - 1))

	pk = &PublicKey{
		Instance: s.ins,
		publicKey: &publicKey{
			seed: pkSeed,
			root: s.xmssNode(skSeed, 0, uint32(s.hPrime), pkSeed, addr),
		},
	}

	sk = &PrivateKey{
		Instance: s.ins,
		privateKey: &privateKey{
			seed:   skSeed,
			prfKey: skPrf,
		},
		publicKey: pk,
	}

	return
}

func (p *params) parseMsg(digest []byte) (
	md []byte,
	idxTree [3]uint32,
	idxLeaf uint32,
) {
	ceil := func(num, den int) int { return (num + den - 1) / den }

	n1 := p.k * p.a
	n2 := p.h - p.h/p.d
	n3 := p.h

	l1 := ceil(n1, 8)
	l2 := ceil(n2, 8)
	l3 := ceil(n3, 8*p.d)

	s1 := digest[0:l1]
	s2 := digest[l1 : l1+l2]
	s3 := digest[l1+l2 : l1+l2+l3]

	md = s1

	twoN := new(big.Int).SetUint64(1)
	twoN.Lsh(twoN, uint(n2))

	b2 := new(big.Int).SetBytes(s2)
	b2.Mod(b2, twoN)

	two32 := new(big.Int).SetUint64(1)
	two32.Lsh(two32, 32)

	idxTree[2] = uint32(new(big.Int).Mod(b2, two32).Uint64())
	b2.Rsh(b2, 32)
	idxTree[1] = uint32(new(big.Int).Mod(b2, two32).Uint64())
	b2.Rsh(b2, 32)
	idxTree[0] = uint32(new(big.Int).Mod(b2, two32).Uint64())
	b2.Rsh(b2, 32)

	twoN = new(big.Int).SetUint64(1)
	twoN.Lsh(twoN, uint(p.h/p.d))

	b3 := new(big.Int).SetBytes(s3)
	b3.Mod(b3, twoN)

	idxLeaf = uint32(new(big.Int).Mod(b3, two32).Uint64())

	return md, idxTree, idxLeaf
}

func (s *state) slhSignInternal(sk *PrivateKey, msg, addRand []byte) ([]byte, error) {
	rnd := make([]byte, s.n)
	s.hasher.PRFMsg(rnd, sk.prfKey, addRand, msg)
	digest := make([]byte, s.m)
	s.hasher.HashMsg(digest, rnd, sk.publicKey.seed, sk.publicKey.root, msg)
	md, idxTree, idxLeaf := s.parseMsg(digest)

	addr := s.newAddress()
	addr.SetTreeAddress(idxTree)
	addr.SetTypeAndClear(addressForsTree)
	addr.SetKeyPairAddress(idxLeaf)

	forsSig := s.forsSign(md, sk.seed, sk.publicKey.seed, addr)
	pkFors := make([]byte, s.forsPkLen())
	s.forsPkFromSig(pkFors, md, forsSig, sk.publicKey.seed, addr)
	htSig := s.htSign(pkFors, sk.seed, sk.publicKey.seed, idxTree, idxLeaf)
	sig := &signature{s.ins, rnd, forsSig, htSig}

	b := cryptobyte.NewFixedBuilder(make([]byte, 0, s.sigLen))
	b.AddValue(sig)
	return b.Bytes()
}

func (s *state) slhVerifyInternal(pk *PublicKey, msg, sigBytes []byte) bool {
	str := cryptobyte.String(sigBytes)
	sig := signature{Instance: s.ins}
	if !sig.Unmarshal(&str) || !str.Empty() {
		return false
	}

	digest := make([]byte, s.m)
	s.hasher.HashMsg(digest, sig.rnd, pk.seed, pk.root, msg)
	md, idxTree, idxLeaf := s.parseMsg(digest)

	addr := s.newAddress()
	addr.SetTreeAddress(idxTree)
	addr.SetTypeAndClear(addressForsTree)
	addr.SetKeyPairAddress(idxLeaf)

	pkFors := make([]byte, s.forsPkLen())
	s.forsPkFromSig(pkFors, md, sig.forsSig, pk.seed, addr)
	return s.htVerify(pkFors, pk.seed, pk.root, idxTree, idxLeaf, sig.htSig)
}
