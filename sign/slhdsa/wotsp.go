package slhdsa

// See FIPS 205 -- Section 5
// Winternitz One-Time Signature Plus Scheme

const (
	wotsW    = 16 // wotsW is w = 2^lg_w, where lg_w = 4.
	wotsLen2 = 3  // wotsLen2 is len_2 fixed to 3.
)

type (
	wotsPublicKey []byte // n bytes
	wotsSignature []byte // wotsLen()*n bytes
)

func (p *params) wotsPkSize() int  { return p.n }
func (p *params) wotsSigSize() int { return p.wotsLen() * p.n }
func (p *params) wotsLen() int     { return 2*p.n + wotsLen2 }

func (ws *wotsSignature) fromBytes(p *params, c *cursor) {
	*ws = c.Next(p.wotsSigSize())
}

// See FIPS 205 -- Section 5 -- Algorithm 5.
func (s *state) chain(x []byte, index, step int, addr address) (out []byte) {
	out = x
	s.F.address.Set(addr)
	for j := index; j < index+step; j++ {
		s.F.address.SetHashAddress(uint32(j))
		s.F.SetMsg(out)
		out = s.F.SumByRef()
	}
	return
}

// See FIPS 205 -- Section 5.1 -- Algorithm 6.
func (s *statePriv) wotsPkGen(pk wotsPublicKey, addr address) {
	s.PRF.address.Set(addr)
	s.PRF.address.SetTypeAndClear(addressWotsPrf)
	s.PRF.address.SetKeyPairAddress(addr.GetKeyPairAddress())

	s.T.address.Set(addr)
	s.T.address.SetTypeAndClear(addressWotsPk)
	s.T.address.SetKeyPairAddress(addr.GetKeyPairAddress())

	s.T.Start()
	wotsLen := s.wotsLen()
	for i := uint32(0); i < uint32(wotsLen); i++ {
		s.PRF.address.SetChainAddress(i)
		sk := s.PRF.SumByRef()

		addr.SetChainAddress(i)
		tmpi := s.chain(sk, 0, wotsW-1, addr)

		s.T.AppendMsg(tmpi)
	}
	s.T.SumCopy(pk)
}

// See FIPS 205 -- Section 5.2 -- Algorithm 7.
func (s *statePriv) wotsSign(sig wotsSignature, msg []byte, addr address) {
	curSig := cursor(sig)
	wotsLen1 := 2 * s.n
	csum := wotsLen1 * (wotsW - 1)

	s.PRF.address.Set(addr)
	s.PRF.address.SetTypeAndClear(addressWotsPrf)
	s.PRF.address.SetKeyPairAddress(addr.GetKeyPairAddress())

	for i := uint32(0); i < uint32(wotsLen1); i++ {
		s.PRF.address.SetChainAddress(i)
		sk := s.PRF.SumByRef()

		addr.SetChainAddress(i)
		msgi := int((msg[i/2] >> ((1 - (i & 1)) << 2)) & 0xF)
		sigi := s.chain(sk, 0, msgi, addr)
		copy(curSig.Next(s.n), sigi)
		csum -= msgi
	}

	for i := uint32(0); i < uint32(wotsLen2); i++ {
		s.PRF.address.SetChainAddress(uint32(wotsLen1) + i)
		sk := s.PRF.SumByRef()

		addr.SetChainAddress(uint32(wotsLen1) + i)
		csumi := (csum >> (8 - 4*i)) & 0xF
		sigi := s.chain(sk, 0, csumi, addr)
		copy(curSig.Next(s.n), sigi)
	}
}

// See FIPS 205 -- Section 5.3 -- Algorithm 8.
func (s *state) wotsPkFromSig(
	sig wotsSignature, msg []byte, addr address,
) wotsPublicKey {
	wotsLen1 := 2 * s.n
	csum := wotsLen1 * (wotsW - 1)

	s.T.address.Set(addr)
	s.T.address.SetTypeAndClear(addressWotsPk)
	s.T.address.SetKeyPairAddress(addr.GetKeyPairAddress())

	s.T.Start()
	curSig := cursor(sig)

	for i := uint32(0); i < uint32(wotsLen1); i++ {
		addr.SetChainAddress(i)
		msgi := int((msg[i/2] >> ((1 - (i & 1)) << 2)) & 0xF)
		sigi := s.chain(curSig.Next(s.n), msgi, wotsW-1-msgi, addr)

		s.T.AppendMsg(sigi)
		csum -= msgi
	}

	for i := uint32(0); i < uint32(wotsLen2); i++ {
		addr.SetChainAddress(uint32(wotsLen1) + i)
		csumi := (csum >> (8 - 4*i)) & 0xF
		sigi := s.chain(curSig.Next(s.n), csumi, wotsW-1-csumi, addr)

		s.T.AppendMsg(sigi)
	}

	return s.T.SumByRef()
}
