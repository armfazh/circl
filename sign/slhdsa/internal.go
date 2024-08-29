package slhdsa

import "encoding/binary"

func (s *state) slhKeyGenInternal(skSeed, skPrf, pkSeed []byte) (sk *PrivateKey, pk *PublicKey) {
	addr := s.newAddress()
	addr.SetLayerAddress(uint32(s.d - 1))
	root := make([]byte, s.n)
	stack := s.newStack(s.hPrime)
	defer stack.clear()

	s.xmssNodeIter(&stack, root, skSeed, 0, uint32(s.hPrime), pkSeed, addr)

	pk = &PublicKey{
		Instance: s.ins,
		publicKey: &publicKey{
			seed: pkSeed,
			root: root,
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

func (p *params) parseMsg(digest []byte) (md []byte, idxTree [3]uint32, idxLeaf uint32) {
	l1 := (p.k*p.a + 7) / 8
	l2 := (p.h - p.h/p.d + 7) / 8
	l3 := (p.h + 8*p.d - 1) / (8 * p.d)

	c := cursor(digest)
	md = c.Next(l1)
	s2 := c.Next(l2)
	s3 := c.Next(l3)

	var b2 [12]byte
	copy(b2[12-len(s2):], s2)
	mask64 := (uint64(1) << (p.h - p.h/p.d)) - 1
	idxTree[0] = uint32(mask64) & binary.BigEndian.Uint32(b2[8:])
	mask64 >>= 32
	idxTree[1] = uint32(mask64) & binary.BigEndian.Uint32(b2[4:])
	mask64 >>= 32
	idxTree[2] = uint32(mask64) & binary.BigEndian.Uint32(b2[0:])

	var b3 [4]byte
	copy(b3[4-len(s3):], s3)
	mask32 := (uint32(1) << (p.h / p.d)) - 1
	idxLeaf = mask32 & binary.BigEndian.Uint32(b3[0:])

	return
}

func (s *state) slhSignInternal(sk *PrivateKey, msg, addRand []byte) ([]byte, error) {
	sigBytes := make([]byte, s.SignatureSize())

	var sig signature
	curSig := cursor(sigBytes)
	if !sig.fromBytes(s.params, &curSig) {
		return nil, ErrSigParse
	}

	s.hasher.PRFMsg(sig.rnd, sk.prfKey, addRand, msg)

	digest := make([]byte, s.m)
	s.hasher.HashMsg(digest, sig.rnd, sk.publicKey.seed, sk.publicKey.root, msg)
	md, idxTree, idxLeaf := s.parseMsg(digest)

	addr := s.newAddress()
	addr.SetTreeAddress(idxTree)
	addr.SetTypeAndClear(addressForsTree)
	addr.SetKeyPairAddress(idxLeaf)

	s.forsSign(sig.forsSig, md, sk.seed, sk.publicKey.seed, addr)
	pkFors := s.forsPkFromSig(md, sig.forsSig, sk.publicKey.seed, addr)
	s.htSign(sig.htSig, pkFors, sk.seed, sk.publicKey.seed, idxTree, idxLeaf)

	return sigBytes, nil
}

func (s *state) slhVerifyInternal(pk *PublicKey, msg, sigBytes []byte) bool {
	var sig signature
	curSig := cursor(sigBytes)
	if len(sigBytes) != s.SignatureSize() || !sig.fromBytes(s.params, &curSig) {
		return false
	}

	digest := make([]byte, s.m)
	s.hasher.HashMsg(digest, sig.rnd, pk.seed, pk.root, msg)
	md, idxTree, idxLeaf := s.parseMsg(digest)

	addr := s.newAddress()
	addr.SetTreeAddress(idxTree)
	addr.SetTypeAndClear(addressForsTree)
	addr.SetKeyPairAddress(idxLeaf)

	pkFors := s.forsPkFromSig(md, sig.forsSig, pk.seed, addr)
	return s.htVerify(pkFors, pk.seed, pk.root, idxTree, idxLeaf, sig.htSig)
}
