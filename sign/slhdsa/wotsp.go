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

func (s *state) chain(out, x []byte, index, step int, pkSeed []byte, addr *address) {
	copy(out, x)
	for j := index; j < index+step; j++ {
		addr.SetHashAddress(uint32(j))
		s.hasher.F(out, pkSeed, addr.Bytes(), out)
	}
}

func (s *state) wotsPkGen(pk wotsPublicKey, skSeed, pkSeed []byte, addr *address) {
	skAddr := *addr
	skAddr.SetTypeAndClear(addressWotsPrf)
	skAddr.SetKeyPairAddress(addr.GetKeyPairAddress())

	sk := make([]byte, s.n)
	wotsLen := s.wotsLen()
	tmp := make([]byte, s.wotsSigLen())
	buf := bytes.NewBuffer(tmp)
	for i := uint32(0); i < uint32(wotsLen); i++ {
		skAddr.SetChainAddress(i)
		s.hasher.PRF(sk, pkSeed, skSeed, skAddr.Bytes())
		addr.SetChainAddress(i)
		s.chain(buf.Next(s.n), sk, 0, wotsW-1, pkSeed, addr)
	}

	wotsPkAddr := *addr
	wotsPkAddr.SetTypeAndClear(addressWotsPk)
	wotsPkAddr.SetKeyPairAddress(addr.GetKeyPairAddress())
	s.hasher.T(pk, pkSeed, wotsPkAddr.Bytes(), tmp)
}

func (s *state) wotsSign(sig wotsSignature, msg, skSeed, pkSeed []byte, addr *address) {
	skAdrr := *addr
	skAdrr.SetTypeAndClear(addressWotsPrf)
	skAdrr.SetKeyPairAddress(addr.GetKeyPairAddress())

	wotsLen1 := 2 * s.n
	csum := wotsLen1 * (wotsW - 1)
	sk := make([]byte, s.n)
	buf := bytes.NewBuffer(sig)
	for i := uint32(0); i < uint32(wotsLen1); i++ {
		skAdrr.SetChainAddress(i)
		s.hasher.PRF(sk, pkSeed, skSeed, skAdrr.Bytes())
		addr.SetChainAddress(i)
		msgi := int((msg[i/2] >> ((1 - (i & 1)) << 2)) & 0xF)
		s.chain(buf.Next(s.n), sk, 0, msgi, pkSeed, addr)
		csum -= msgi
	}

	for i := uint32(0); i < uint32(wotsLen2); i++ {
		skAdrr.SetChainAddress(uint32(wotsLen1) + i)
		s.hasher.PRF(sk, pkSeed, skSeed, skAdrr.Bytes())
		addr.SetChainAddress(uint32(wotsLen1) + i)
		s.chain(buf.Next(s.n), sk, 0, (csum>>(8-4*i))&0xF, pkSeed, addr)
	}
}

func (s *state) wotsPkFromSig(pk wotsPublicKey, sig wotsSignature, msg, pkSeed []byte, addr *address) {
	wotsLen1 := 2 * s.n
	csum := wotsLen1 * (wotsW - 1)
	tmp := make([]byte, s.wotsSigLen())
	buf := bytes.NewBuffer(tmp)
	sigBuf := bytes.NewBuffer(sig)
	for i := uint32(0); i < uint32(wotsLen1); i++ {
		addr.SetChainAddress(i)
		msgi := int((msg[i/2] >> ((1 - (i & 1)) << 2)) & 0xF)
		s.chain(buf.Next(s.n), sigBuf.Next(s.n), msgi, wotsW-1-msgi, pkSeed, addr)
		csum -= msgi
	}

	for i := uint32(0); i < uint32(wotsLen2); i++ {
		addr.SetChainAddress(uint32(wotsLen1) + i)
		csumi := (csum >> (8 - 4*i)) & 0xF
		s.chain(buf.Next(s.n), sigBuf.Next(s.n), csumi, wotsW-1-csumi, pkSeed, addr)
	}

	wotsPkAddr := *addr
	wotsPkAddr.SetTypeAndClear(addressWotsPk)
	wotsPkAddr.SetKeyPairAddress(addr.GetKeyPairAddress())
	s.hasher.T(pk, pkSeed, wotsPkAddr.Bytes(), tmp)
}
