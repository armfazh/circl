package slhdsa

import (
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"io"

	"github.com/cloudflare/circl/internal/sha3"
)

type hasher interface {
	PRFMsg(skPrf, optRand, msg []byte) (out []byte)
	HashMsg(r, pkSeed, pkRoot, msg []byte) (out []byte)
	PRF(pkSeed, skSeed []byte, addr address) (out []byte)
	T(pkSeed []byte, addr address, msgs [][]byte) (out []byte)
	H(pkSeed []byte, addr address, msgs [2][]byte) (out []byte)
	F(pkSeed []byte, addr address, msg []byte) (out []byte)
}

func concat(w io.Writer, items ...[]byte) {
	for _, it := range items {
		_, err := w.Write(it)
		if err != nil {
			panic(ErrWriting)
		}
	}
}

type shakeFn struct {
	n     uint
	m     uint
	state sha3.State
}

func (p *shakeFn) doShake(size uint) (out []byte) {
	out = make([]byte, size)

	_, err := io.ReadFull(&p.state, out)
	if err != nil {
		panic(ErrReading)
	}

	return
}

func (p *shakeFn) HashMsg(r, pkSeed, pkRoot, msg []byte) (out []byte) {
	p.state.Reset()
	concat(&p.state, r, pkSeed, pkRoot, msg)
	return p.doShake(p.m)
}

func (p *shakeFn) PRF(pkSeed, skSeed []byte, addr address) (out []byte) {
	p.state.Reset()
	concat(&p.state, pkSeed, addr.Bytes(), skSeed)
	return p.doShake(p.n)
}

func (p *shakeFn) PRFMsg(skPrf, optRand, msg []byte) (out []byte) {
	p.state.Reset()
	concat(&p.state, skPrf, optRand, msg)
	return p.doShake(p.n)
}

func (p *shakeFn) F(pkSeed []byte, addr address, msg []byte) (out []byte) {
	p.state.Reset()
	concat(&p.state, pkSeed, addr.Bytes(), msg)
	return p.doShake(p.n)
}

func (p *shakeFn) H(pkSeed []byte, addr address, msgs [2][]byte) (out []byte) {
	p.state.Reset()
	concat(&p.state, pkSeed, addr.Bytes())
	concat(&p.state, msgs[:]...)
	return p.doShake(p.n)
}

func (p *shakeFn) T(pkSeed []byte, addr address, msgs [][]byte) (out []byte) {
	p.state.Reset()
	concat(&p.state, pkSeed, addr.Bytes())
	concat(&p.state, msgs...)
	return p.doShake(p.n)
}

type sha2Fn struct {
	n      uint
	m      uint
	padLen uint
	sha2Fn crypto.Hash
	state  hash.Hash
}

func (p *sha2Fn) mgf1(mgfSeed []byte, maskLen uint32) (out []byte) {
	out = make([]byte, 0, maskLen)
	hLen := uint32(p.state.Size())
	end := (maskLen + hLen - 1) / hLen

	for counter := uint32(0); counter < end; counter++ {
		p.state.Reset()
		concat(p.state, mgfSeed, binary.BigEndian.AppendUint32(nil, counter))
		out = p.state.Sum(out)
	}

	return out[:maskLen]
}

func (p *sha2Fn) HashMsg(r, pkSeed, pkRoot, msg []byte) (out []byte) {
	mgfSeed := append(append([]byte{}, r...), pkSeed...)

	p.state.Reset()
	concat(p.state, r, pkSeed, pkRoot, msg)
	mgfSeed = p.state.Sum(mgfSeed)
	return p.mgf1(mgfSeed, uint32(p.m))
}

func (p *sha2Fn) PRF(pkSeed, skSeed []byte, addr address) (out []byte) {
	h := sha256.New()
	concat(h, pkSeed, make([]byte, 64-p.n), addr.CompressedBytes(), skSeed)
	return h.Sum(nil)[:p.n]
}

func (p *sha2Fn) PRFMsg(skPrf, optRand, msg []byte) (out []byte) {
	mac := hmac.New(p.sha2Fn.New, skPrf)
	concat(mac, optRand, msg)
	return mac.Sum(nil)[:p.n]
}

func (p *sha2Fn) F(pkSeed []byte, addr address, msg []byte) (out []byte) {
	h := sha256.New()
	concat(h, pkSeed, make([]byte, 64-p.n), addr.CompressedBytes(), msg)
	return h.Sum(nil)[:p.n]
}

func (p *sha2Fn) H(pkSeed []byte, addr address, msgs [2][]byte) (out []byte) {
	p.state.Reset()
	concat(p.state, pkSeed, make([]byte, p.padLen-p.n), addr.CompressedBytes())
	concat(p.state, msgs[:]...)
	return p.state.Sum(nil)[:p.n]
}

func (p *sha2Fn) T(pkSeed []byte, addr address, msgs [][]byte) (out []byte) {
	p.state.Reset()
	concat(p.state, pkSeed, make([]byte, p.padLen-p.n), addr.CompressedBytes())
	concat(p.state, msgs[:]...)
	return p.state.Sum(nil)[:p.n]
}
