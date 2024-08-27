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

func (p *shakeFn) PRFMsg(out, skPrf, optRand, msg []byte) {
	p.Reset()
	concat(p, skPrf, optRand, msg)
	_, _ = p.Read(out)
}

type sha2Fn struct {
	sum    [sha512.Size]byte
	state  hash.Hash
	hmacFn crypto.Hash
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

func (p *sha2Fn) PRFMsg(out, skPrf, optRand, msg []byte) {
	mac := hmac.New(p.hmacFn.New, skPrf)
	concat(mac, optRand, msg)
	copy(out, mac.Sum(p.sum[:0]))
}

type rw interface {
	Reset()
	Write([]byte)
	Sum([]byte)
}

type sha2rw struct {
	sum   [sha512.Size]byte
	state hash.Hash
}

func (s *sha2rw) Reset()          { s.state.Reset() }
func (s *sha2rw) Write(in []byte) { _, _ = s.state.Write(in) }
func (s *sha2rw) Sum(out []byte)  { copy(out, s.state.Sum(s.sum[:0])) }

type sha3rw struct{ state sha3.State }

func (s *sha3rw) Reset()          { s.state.Reset() }
func (s *sha3rw) Write(in []byte) { _, _ = s.state.Write(in) }
func (s *sha3rw) Sum(out []byte)  { _, _ = s.state.Read(out) }
