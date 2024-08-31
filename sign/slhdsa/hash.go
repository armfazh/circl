package slhdsa

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"hash"
	"io"

	"github.com/cloudflare/circl/internal/sha3"
)

type concat0rw struct{ buf bytes.Buffer }

func (c *concat0rw) Reset()                            {}
func (c *concat0rw) Write(p []byte) (n int, err error) { return }
func (c *concat0rw) Sum(out []byte)                    { c.buf.Read(out) }

func (p *params) PRFMsg(out, skPrf, optRand, msg []byte) {
	if p.isSha2 {
		var sum [sha512.Size]byte
		var h crypto.Hash
		if p.n == 16 {
			h = crypto.SHA256
		} else {
			h = crypto.SHA512
		}

		mac := hmac.New(h.New, skPrf)
		concat(mac, optRand, msg)
		copy(out, mac.Sum(sum[:0]))
	} else {
		state := sha3.NewShake256()
		concat(&state, skPrf, optRand, msg)
		_, _ = state.Read(out)
	}
}

func (p *params) HashMsg(out, r, pkSeed, pkRoot, msg []byte) {
	if p.isSha2 {
		var state hash.Hash
		if p.n == 16 {
			state = sha256.New()
		} else {
			state = sha512.New()
		}

		mgfSeed := append(append([]byte{}, r...), pkSeed...)
		concat(state, r, pkSeed, pkRoot, msg)
		p.mgf1(state, out, state.Sum(mgfSeed))
	} else {
		state := sha3.NewShake256()
		concat(&state, r, pkSeed, pkRoot, msg)
		_, _ = state.Read(out)
	}
}

func (p *params) mgf1(state hash.Hash, out, mgfSeed []byte) {
	hLen := state.Size()
	end := (len(out) + hLen - 1) / hLen
	buf := make([]byte, 0, end*hLen)
	var counterBytes [4]byte
	for counter := 0; counter < end; counter++ {
		state.Reset()
		binary.BigEndian.PutUint32(counterBytes[:], uint32(counter))
		concat(state, mgfSeed, counterBytes[:])
		buf = state.Sum(buf)
	}
	copy(out, buf)
}

func concat(w io.Writer, items ...[]byte) {
	for _, it := range items {
		_, err := w.Write(it)
		if err != nil {
			panic(ErrWriting)
		}
	}
}
