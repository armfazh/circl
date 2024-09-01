package slhdsa

import "encoding/binary"

func slhKeyGenInternal(p *params, skSeed, skPrf, pkSeed []byte) (priv PrivateKey, pub PublicKey) {
	state := p.NewStatePriv(skSeed, pkSeed)
	defer state.Clear()

	stack := p.NewStack(p.hPrime)
	defer stack.Clear()

	addr := p.NewAddress()
	addr.SetLayerAddress(uint32(p.d - 1))
	pkRoot := make([]byte, p.n)
	state.xmssNodeIter(&stack, pkRoot, 0, uint32(p.hPrime), addr)

	pub.Instance = p.ins
	pub.seed = pkSeed
	pub.root = pkRoot

	priv.Instance = p.ins
	priv.prfKey = skPrf
	priv.seed = skSeed
	priv.publicKey = pub

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

func slhSignInternal(p *params, sk *PrivateKey, msg, addRand []byte) ([]byte, error) {
	sigBytes := make([]byte, p.SignatureSize())

	var sig signature
	curSig := cursor(sigBytes)
	if !sig.fromBytes(p, &curSig) {
		return nil, ErrSigParse
	}

	err := p.PRFMsg(sig.rnd, sk.prfKey, addRand, msg)
	if err != nil {
		return nil, err
	}

	digest := make([]byte, p.m)
	err = p.HashMsg(digest, sig.rnd, sk.publicKey.seed, sk.publicKey.root, msg)
	if err != nil {
		return nil, err
	}

	md, idxTree, idxLeaf := p.parseMsg(digest)
	addr := p.NewAddress()
	addr.SetTreeAddress(idxTree)
	addr.SetTypeAndClear(addressForsTree)
	addr.SetKeyPairAddress(idxLeaf)

	state := p.NewStatePriv(sk.seed, sk.publicKey.seed)
	defer state.Clear()

	state.forsSign(sig.forsSig, md, addr)
	pkFors := state.forsPkFromSig(md, sig.forsSig, addr)
	state.htSign(sig.htSig, pkFors, idxTree, idxLeaf)

	return sigBytes, nil
}

func slhVerifyInternal(p *params, pub *PublicKey, msg, sigBytes []byte) bool {
	var sig signature
	curSig := cursor(sigBytes)
	if len(sigBytes) != p.SignatureSize() || !sig.fromBytes(p, &curSig) {
		return false
	}

	digest := make([]byte, p.m)
	err := p.HashMsg(digest, sig.rnd, pub.seed, pub.root, msg)
	if err != nil {
		return false
	}

	md, idxTree, idxLeaf := p.parseMsg(digest)
	addr := p.NewAddress()
	addr.SetTreeAddress(idxTree)
	addr.SetTypeAndClear(addressForsTree)
	addr.SetKeyPairAddress(idxLeaf)

	state := p.NewStatePub(pub.seed)
	defer state.Clear()

	pkFors := state.forsPkFromSig(md, sig.forsSig, addr)
	return state.htVerify(pkFors, pub.root, idxTree, idxLeaf, sig.htSig)
}
