package slhdsa

import (
	"bytes"

	"golang.org/x/crypto/cryptobyte"
)

type (
	wotsPublicKey []byte // n bytes
	wotsSignature []byte // wotsLen*n bytes
)

func (ws wotsSignature) Marshal(b *cryptobyte.Builder) error { b.AddBytes(ws); return nil }
func (ws *wotsSignature) Unmarshal(p *params, str *cryptobyte.String) bool {
	*ws = make([]byte, p.wotsSigLen())
	return str.CopyBytes(*ws)
}

const (
	wotsW    = 16
	wotsLen2 = 3
)

func (p *params) wotsLen() int    { return 2*p.n + wotsLen2 }
func (p *params) wotsSigLen() int { return p.wotsLen() * p.n }
func (p *params) wotsPkLen() int  { return p.n }

func (s *state) chain(x []byte, index, step int, pkSeed []byte, addr *address) (out []byte) {
	out = x
	s.f.SetPkSeed(pkSeed)
	for j := index; j < index+step; j++ {
		addr.SetHashAddress(uint32(j))
		s.f.SetAddress(addr)
		s.f.SetMsg(out)
		out = s.f.SumByRef()
	}
	return
}

func (s *state) wotsPkGen(pk wotsPublicKey, skSeed, pkSeed []byte, addr *address) {
	skAddr := *addr
	skAddr.SetTypeAndClear(addressWotsPrf)
	skAddr.SetKeyPairAddress(addr.GetKeyPairAddress())

	s.prf.SetPkSeed(pkSeed)
	s.prf.SetSkSeed(skSeed)

	wotsPkAddr := *addr
	wotsPkAddr.SetTypeAndClear(addressWotsPk)
	wotsPkAddr.SetKeyPairAddress(addr.GetKeyPairAddress())

	s.t.SetPkSeed(pkSeed)
	s.t.SetAddress(&wotsPkAddr)
	s.t.Start()

	wotsLen := s.wotsLen()
	for i := uint32(0); i < uint32(wotsLen); i++ {
		skAddr.SetChainAddress(i)
		s.prf.SetAddress(&skAddr)
		sk := s.prf.SumByRef()
		addr.SetChainAddress(i)
		tmpi := s.chain(sk, 0, wotsW-1, pkSeed, addr)
		s.t.AppendMsg(tmpi)
	}
	s.t.SumCopy(pk)
}

func (s *state) wotsSign(sig wotsSignature, msg, skSeed, pkSeed []byte, addr *address) {
	buf := bytes.NewBuffer(sig)
	wotsLen1 := 2 * s.n
	csum := wotsLen1 * (wotsW - 1)
	s.prf.SetPkSeed(pkSeed)
	s.prf.SetSkSeed(skSeed)

	skAddr := *addr
	skAddr.SetTypeAndClear(addressWotsPrf)
	skAddr.SetKeyPairAddress(addr.GetKeyPairAddress())

	for i := uint32(0); i < uint32(wotsLen1); i++ {
		skAddr.SetChainAddress(i)
		s.prf.SetAddress(&skAddr)
		sk := s.prf.SumByRef()
		addr.SetChainAddress(i)
		msgi := int((msg[i/2] >> ((1 - (i & 1)) << 2)) & 0xF)
		sigi := s.chain(sk, 0, msgi, pkSeed, addr)
		copy(buf.Next(s.n), sigi)
		csum -= msgi
	}

	for i := uint32(0); i < uint32(wotsLen2); i++ {
		skAddr.SetChainAddress(uint32(wotsLen1) + i)
		s.prf.SetAddress(&skAddr)
		sk := s.prf.SumByRef()
		addr.SetChainAddress(uint32(wotsLen1) + i)
		sigi := s.chain(sk, 0, (csum>>(8-4*i))&0xF, pkSeed, addr)
		copy(buf.Next(s.n), sigi)
	}
}

func (s *state) wotsPkFromSig(sig wotsSignature, msg, pkSeed []byte, addr *address) (pk wotsPublicKey) {
	sigBuf := bytes.NewBuffer(sig)
	wotsLen1 := 2 * s.n
	csum := wotsLen1 * (wotsW - 1)

	wotsPkAddr := *addr
	wotsPkAddr.SetTypeAndClear(addressWotsPk)
	wotsPkAddr.SetKeyPairAddress(addr.GetKeyPairAddress())

	s.t.SetPkSeed(pkSeed)
	s.t.SetAddress(&wotsPkAddr)
	s.t.Start()
	for i := uint32(0); i < uint32(wotsLen1); i++ {
		addr.SetChainAddress(i)
		msgi := int((msg[i/2] >> ((1 - (i & 1)) << 2)) & 0xF)
		sigi := s.chain(sigBuf.Next(s.n), msgi, wotsW-1-msgi, pkSeed, addr)
		s.t.AppendMsg(sigi)
		csum -= msgi
	}
	for i := uint32(0); i < uint32(wotsLen2); i++ {
		addr.SetChainAddress(uint32(wotsLen1) + i)
		csumi := (csum >> (8 - 4*i)) & 0xF
		sigi := s.chain(sigBuf.Next(s.n), csumi, wotsW-1-csumi, pkSeed, addr)
		s.t.AppendMsg(sigi)
	}
	// s.t.SumCopy(pk)
	pk = s.t.SumByRef()
	return
}
