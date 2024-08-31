package slhdsa

const (
	wotsW    = 16
	wotsLen2 = 3
)

type (
	wotsPublicKey []byte // n bytes
	wotsSignature []byte // wotsLen()*n bytes
)

func (p *params) wotsPkSize() int  { return p.n }
func (p *params) wotsSigSize() int { return p.wotsLen() * p.n }
func (p *params) wotsLen() int     { return 2*p.n + wotsLen2 }

func (ws *wotsSignature) fromBytes(p *params, c *cursor) { *ws = c.Next(p.wotsSigSize()) }

func (s *state) chain(x, pkSeed []byte, index, step int, addr *address) (out []byte) {
	out = x
	s.f.SetAddress(addr)
	for j := index; j < index+step; j++ {
		s.f.address.SetHashAddress(uint32(j))
		s.f.SetMsg(out)
		out = s.F_SumByRef()
	}
	return
}

func (s *state) wotsPkGen(pk wotsPublicKey, skSeed, pkSeed []byte, addr *address) {
	s.prf.SetAddress(addr)
	s.prf.address.SetTypeAndClear(addressWotsPrf)
	s.prf.address.SetKeyPairAddress(addr.GetKeyPairAddress())

	s.t.SetAddress(addr)
	s.t.address.SetTypeAndClear(addressWotsPk)
	s.t.address.SetKeyPairAddress(addr.GetKeyPairAddress())

	s.T_Start()
	wotsLen := s.wotsLen()
	for i := uint32(0); i < uint32(wotsLen); i++ {
		s.prf.address.SetChainAddress(i)
		sk := s.PRF_SumByRef()

		addr.SetChainAddress(i)
		tmpi := s.chain(sk, pkSeed, 0, wotsW-1, addr)

		s.T_AppendMsg(tmpi)
	}
	s.T_SumCopy(pk)
}

func (s *state) wotsSign(sig wotsSignature, msg, skSeed, pkSeed []byte, addr *address) {
	curSig := cursor(sig)
	wotsLen1 := 2 * s.n
	csum := wotsLen1 * (wotsW - 1)

	s.prf.SetAddress(addr)
	s.prf.address.SetTypeAndClear(addressWotsPrf)
	s.prf.address.SetKeyPairAddress(addr.GetKeyPairAddress())

	for i := uint32(0); i < uint32(wotsLen1); i++ {
		s.prf.address.SetChainAddress(i)
		sk := s.PRF_SumByRef()

		addr.SetChainAddress(i)
		msgi := int((msg[i/2] >> ((1 - (i & 1)) << 2)) & 0xF)
		sigi := s.chain(sk, pkSeed, 0, msgi, addr)
		copy(curSig.Next(s.n), sigi)
		csum -= msgi
	}

	for i := uint32(0); i < uint32(wotsLen2); i++ {
		s.prf.address.SetChainAddress(uint32(wotsLen1) + i)
		sk := s.PRF_SumByRef()

		addr.SetChainAddress(uint32(wotsLen1) + i)
		csumi := (csum >> (8 - 4*i)) & 0xF
		sigi := s.chain(sk, pkSeed, 0, csumi, addr)
		copy(curSig.Next(s.n), sigi)
	}
}

func (s *state) wotsPkFromSig(sig wotsSignature, msg, pkSeed []byte, addr *address) wotsPublicKey {
	curSig := cursor(sig)
	wotsLen1 := 2 * s.n
	csum := wotsLen1 * (wotsW - 1)

	s.t.SetAddress(addr)
	s.t.address.SetTypeAndClear(addressWotsPk)
	s.t.address.SetKeyPairAddress(addr.GetKeyPairAddress())

	s.T_Start()
	for i := uint32(0); i < uint32(wotsLen1); i++ {
		addr.SetChainAddress(i)
		msgi := int((msg[i/2] >> ((1 - (i & 1)) << 2)) & 0xF)
		sigi := s.chain(curSig.Next(s.n), pkSeed, msgi, wotsW-1-msgi, addr)

		s.T_AppendMsg(sigi)
		csum -= msgi
	}
	for i := uint32(0); i < uint32(wotsLen2); i++ {
		addr.SetChainAddress(uint32(wotsLen1) + i)
		csumi := (csum >> (8 - 4*i)) & 0xF
		sigi := s.chain(curSig.Next(s.n), pkSeed, csumi, wotsW-1-csumi, addr)

		s.T_AppendMsg(sigi)
	}

	return s.T_SumByRef()
}
