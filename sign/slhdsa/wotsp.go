package slhdsa

import "golang.org/x/crypto/cryptobyte"

type (
	wotsPublicKey []byte
	wotsSignature [][]byte
)

func (ws *wotsSignature) Marshal(b *cryptobyte.Builder) (err error) {
	for i := range *ws {
		b.AddBytes((*ws)[i])
	}
	return
}

func (ws *wotsSignature) Unmarshal(p *params, str *cryptobyte.String) bool {
	wotsLen := p.wotsLen()
	*ws = make(wotsSignature, wotsLen)
	buf := make([]byte, p.n*wotsLen)
	for i := uint(0); i < wotsLen; i++ {
		(*ws)[i] = buf[:p.n]
		if !str.CopyBytes((*ws)[i]) {
			return false
		}
		buf = buf[p.n:]
	}

	return true
}

const (
	wotsW    = uint(16)
	wotsLen2 = 3
)

func (p *params) wotsLen() uint { return 2*p.n + wotsLen2 }

func (s *state) chain(x []byte, index, step uint, pkSeed []byte, addr address) (out []byte) {
	out = x
	for j := index; j < index+step; j++ {
		addr.SetHashAddress(uint32(j))
		out = s.hasher.F(pkSeed, addr, out)
	}
	return
}

func (s *state) wotsPkGen(skSeed, pkSeed []byte, addr address) wotsPublicKey {
	skAddr := addr
	skAddr.SetTypeAndClear(addressWotsPrf)
	skAddr.SetKeyPairAddress(addr.GetKeyPairAddress())

	wotsLen := s.wotsLen()
	tmp := make([][]byte, wotsLen)
	for i := uint32(0); i < uint32(wotsLen); i++ {
		skAddr.SetChainAddress(i)
		sk := s.hasher.PRF(pkSeed, skSeed, skAddr)
		addr.SetChainAddress(i)
		tmp[i] = s.chain(sk, 0, wotsW-1, pkSeed, addr)
	}

	wotsPkAddr := addr
	wotsPkAddr.SetTypeAndClear(addressWotsPk)
	wotsPkAddr.SetKeyPairAddress(addr.GetKeyPairAddress())
	return s.hasher.T(pkSeed, wotsPkAddr, tmp)
}

func (s *state) wotsSign(msg, skSeed, pkSeed []byte, addr address) (sig wotsSignature) {
	csum := uint(0)
	for i := uint(0); i < s.n; i++ {
		csum += wotsW - 1 - uint((msg[i]>>4)&0xF)
		csum += wotsW - 1 - uint(msg[i]&0xF)
	}
	csum <<= 4 // Same as csum = csum << ((8 - ((wotsLen2 * lgW) % 8)) % 8)

	skAdrr := addr
	skAdrr.SetTypeAndClear(addressWotsPrf)
	skAdrr.SetKeyPairAddress(addr.GetKeyPairAddress())

	wotsLen := s.wotsLen()
	sig = make([][]byte, wotsLen)
	for i := uint32(0); i < uint32(s.n); i++ {
		skAdrr.SetChainAddress(2 * i)
		sk := s.hasher.PRF(pkSeed, skSeed, skAdrr)
		addr.SetChainAddress(2 * i)
		sig[2*i] = s.chain(sk, 0, uint((msg[i]>>4)&0xF), pkSeed, addr)

		skAdrr.SetChainAddress(2*i + 1)
		sk = s.hasher.PRF(pkSeed, skSeed, skAdrr)
		addr.SetChainAddress(2*i + 1)
		sig[2*i+1] = s.chain(sk, 0, uint(msg[i]&0xF), pkSeed, addr)
	}

	wotsLen1 := uint32(2 * s.n)
	for i := uint32(0); i < wotsLen2; i++ {
		skAdrr.SetChainAddress(wotsLen1 + i)
		sk := s.hasher.PRF(pkSeed, skSeed, skAdrr)
		addr.SetChainAddress(wotsLen1 + i)
		sig[wotsLen1+i] = s.chain(sk, 0, (csum>>(12-4*i))&0xF, pkSeed, addr)
	}

	return sig
}

func (s *state) wotsPkFromSig(sig wotsSignature, msg, pkSeed []byte, addr address) (pk wotsPublicKey) {
	csum := uint(0)
	for i := uint(0); i < s.n; i++ {
		csum += wotsW - 1 - uint((msg[i]>>4)&0xF)
		csum += wotsW - 1 - uint(msg[i]&0xF)
	}
	csum <<= 4 // Same as csum = csum << ((8 - ((wotsLen2 * lgW) % 8)) % 8)

	wotsLen := s.wotsLen()
	tmp := make([][]byte, wotsLen)
	for i := uint32(0); i < uint32(s.n); i++ {
		addr.SetChainAddress(2 * i)
		msgi := uint((msg[i] >> 4) & 0xF)
		tmp[2*i] = s.chain(sig[2*i], msgi, wotsW-1-msgi, pkSeed, addr)

		addr.SetChainAddress(2*i + 1)
		msgi = uint(msg[i] & 0xF)
		tmp[2*i+1] = s.chain(sig[2*i+1], msgi, wotsW-1-msgi, pkSeed, addr)
	}

	wotsLen1 := uint32(2 * s.n)
	for i := uint32(0); i < wotsLen2; i++ {
		addr.SetChainAddress(wotsLen1 + i)
		csumi := (csum >> (12 - 4*i)) & 0xF
		tmp[wotsLen1+i] = s.chain(sig[wotsLen1+i], csumi, wotsW-1-csumi, pkSeed, addr)
	}

	wotsPkAddr := addr
	wotsPkAddr.SetTypeAndClear(addressWotsPk)
	wotsPkAddr.SetKeyPairAddress(addr.GetKeyPairAddress())
	return s.hasher.T(pkSeed, wotsPkAddr, tmp)
}
