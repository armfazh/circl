package slhdsa

import (
	"crypto"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"hash"
	"io"

	"github.com/cloudflare/circl/internal/sha3"
)

type hasher interface {
	PRFMsg(out, skPrf, optRand, msg []byte)
	HashMsg(out, r, pkSeed, pkRoot, msg []byte)
	PRF(out, pkSeed, skSeed, addr []byte)
	T(out, pkSeed, addr, msgs []byte)
	H(out, pkSeed, addr, msg0, msg1 []byte)
	F(out, pkSeed, addr, msg []byte)
}

func concat(w io.Writer, items ...[]byte) {
	for _, it := range items {
		_, err := w.Write(it)
		if err != nil {
			panic(ErrWriting)
		}
	}
}

type shakeFn struct{ sha3.State }

func (p *shakeFn) HashMsg(out, r, pkSeed, pkRoot, msg []byte) {
	p.Reset()
	concat(p, r, pkSeed, pkRoot, msg)
	_, _ = p.Read(out)
}

func (p *shakeFn) PRF(out, pkSeed, skSeed, addr []byte) {
	p.Reset()
	concat(p, pkSeed, addr, skSeed)
	_, _ = p.Read(out)
}

func (p *shakeFn) PRFMsg(out, skPrf, optRand, msg []byte) {
	p.Reset()
	concat(p, skPrf, optRand, msg)
	_, _ = p.Read(out)
}

func (p *shakeFn) F(out, pkSeed, addr, msg []byte) {
	p.Reset()
	concat(p, pkSeed, addr, msg)
	_, _ = p.Read(out)
}

func (p *shakeFn) H(out, pkSeed, addr, msg0, msg1 []byte) {
	p.Reset()
	concat(p, pkSeed, addr, msg0, msg1)
	_, _ = p.Read(out)
}

func (p *shakeFn) T(out, pkSeed, addr, msgs []byte) {
	p.Reset()
	concat(p, pkSeed, addr, msgs)
	_, _ = p.Read(out)
}

type sha2Fn struct {
	sum             [sha512.Size]byte
	zeros           [128]byte
	state, state256 hash.Hash
	n, padLen       int
	hmacFn          crypto.Hash
}

func (p *sha2Fn) mgf1(out, mgfSeed []byte) {
	hLen := p.state.Size()
	end := (len(out) + hLen - 1) / hLen
	buf := make([]byte, 0, end*hLen)
	counterBytes := (&[4]byte{})[:]
	for counter := 0; counter < end; counter++ {
		p.state.Reset()
		binary.BigEndian.PutUint32(counterBytes, uint32(counter))
		concat(p.state, mgfSeed, counterBytes)
		buf = p.state.Sum(buf)
	}
	copy(out, buf)
}

func (p *sha2Fn) HashMsg(out, r, pkSeed, pkRoot, msg []byte) {
	mgfSeed := append(append([]byte{}, r...), pkSeed...)

	p.state.Reset()
	concat(p.state, r, pkSeed, pkRoot, msg)
	p.mgf1(out, p.state.Sum(mgfSeed))
}

func (p *sha2Fn) PRF(out, pkSeed, skSeed, addr []byte) {
	p.state256.Reset()
	concat(p.state256, pkSeed, p.zeros[:64-p.n], addr, skSeed)
	copy(out, p.state256.Sum(p.sum[:0]))
}

func (p *sha2Fn) PRFMsg(out, skPrf, optRand, msg []byte) {
	mac := hmac.New(p.hmacFn.New, skPrf)
	concat(mac, optRand, msg)
	copy(out, mac.Sum(p.sum[:0]))
}

func (p *sha2Fn) F(out, pkSeed, addr, msg []byte) {
	p.state256.Reset()
	concat(p.state256, pkSeed, p.zeros[:64-p.n], addr, msg)
	copy(out, p.state256.Sum(p.sum[:0]))
}

func (p *sha2Fn) H(out, pkSeed, addr, msg0, msg1 []byte) {
	p.state.Reset()
	concat(p.state, pkSeed, p.zeros[:p.padLen-p.n], addr, msg0, msg1)
	copy(out, p.state.Sum(p.sum[:0]))
}

func (p *sha2Fn) T(out, pkSeed, addr, msgs []byte) {
	p.state.Reset()
	concat(p.state, pkSeed, p.zeros[:p.padLen-p.n], addr, msgs)
	copy(out, p.state.Sum(p.sum[:0]))
}
