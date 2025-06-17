// Package expander generates arbitrary bytes from an XOF or Hash function.
package expander

import (
	"crypto"
	"encoding/binary"
	"errors"
	"hash"
	"io"

	"github.com/cloudflare/circl/xof"
)

type Expander interface {
	// Expand generates a pseudo-random byte string of a determined length by
	// expanding an input string.
	Expand(in []byte, length uint) (pseudo []byte)
}

type expanderMD struct {
	h    hash.Hash
	dst  []byte
	zPad []byte
}

// NewExpanderMD returns a hash function based on a Merkle-Damgård hash function.
func NewExpanderMD(h crypto.Hash, dst []byte) *expanderMD {
	hh := h.New()
	return &expanderMD{hh, dst, make([]byte, hh.BlockSize())}
}

func (e *expanderMD) calcDSTPrime() []byte {
	var dstPrime []byte
	if l := len(e.dst); l > maxDSTLength {
		e.h.Reset()
		mustWrite(e.h, longDSTPrefix[:])
		mustWrite(e.h, e.dst)
		dstPrime = e.h.Sum(nil)
	} else {
		dstPrime = make([]byte, l, l+1)
		copy(dstPrime, e.dst)
	}
	return append(dstPrime, byte(len(dstPrime)))
}

func (e *expanderMD) Expand(in []byte, n uint) []byte {
	e.h.Reset()
	bLen := uint(e.h.Size())
	ell := (n + (bLen - 1)) / bLen
	if ell > 255 {
		panic(errorLongOutput)
	}

	// zPad := make([]byte, e.h.BlockSize())
	libStr := []byte{0, 0}
	libStr[0] = byte((n >> 8) & 0xFF)
	libStr[1] = byte(n & 0xFF)
	dstPrime := e.calcDSTPrime()

	mustWrite(e.h, e.zPad)
	mustWrite(e.h, in)
	mustWrite(e.h, libStr)
	mustWrite(e.h, []byte{0})
	mustWrite(e.h, dstPrime)
	b0 := e.h.Sum(nil)

	e.h.Reset()
	mustWrite(e.h, b0)
	mustWrite(e.h, []byte{1})
	mustWrite(e.h, dstPrime)
	bi := e.h.Sum(nil)
	
	pseudo := make([]byte, 0, n)
	pseudo = append(pseudo, bi...)

	bbb := make([]byte, e.h.Size())
	for i := uint(2); i <= ell; i++ {
		e.h.Reset()
		for i := range b0 {
			bi[i] ^= b0[i]
		}
		mustWrite(e.h, bi)
		mustWrite(e.h, []byte{byte(i)})
		mustWrite(e.h, dstPrime)
		bi = e.h.Sum(bbb[:0])
		pseudo = append(pseudo, bi...)
	}
	return pseudo[0:n]
}

// expanderXOF is based on an extendable output function.
type expanderXOF struct {
	id        xof.ID
	kSecLevel uint
	dst       []byte
}

// NewExpanderXOF returns an Expander based on an extendable output function.
// The kSecLevel parameter is the target security level in bits, and dst is
// a domain separation string.
func NewExpanderXOF(id xof.ID, kSecLevel uint, dst []byte) *expanderXOF {
	return &expanderXOF{id, kSecLevel, dst}
}

// Expand panics if output's length is longer than 2^16 bytes.
func (e *expanderXOF) Expand(in []byte, n uint) []byte {
	bLen := []byte{0, 0}
	binary.BigEndian.PutUint16(bLen, uint16(n))
	pseudo := make([]byte, n)
	dstPrime := e.calcDSTPrime()

	H := e.id.New()
	mustWrite(H, in)
	mustWrite(H, bLen)
	mustWrite(H, dstPrime)
	mustReadFull(H, pseudo)
	return pseudo
}

func (e *expanderXOF) calcDSTPrime() []byte {
	var dstPrime []byte
	if l := len(e.dst); l > maxDSTLength {
		H := e.id.New()
		mustWrite(H, longDSTPrefix[:])
		mustWrite(H, e.dst)
		max := ((2 * e.kSecLevel) + 7) / 8
		dstPrime = make([]byte, max, max+1)
		mustReadFull(H, dstPrime)
	} else {
		dstPrime = make([]byte, l, l+1)
		copy(dstPrime, e.dst)
	}
	return append(dstPrime, byte(len(dstPrime)))
}

func mustWrite(w io.Writer, b []byte) {
	if n, err := w.Write(b); err != nil || n != len(b) {
		panic(err)
	}
}

func mustReadFull(r io.Reader, b []byte) {
	if n, err := io.ReadFull(r, b); err != nil || n != len(b) {
		panic(err)
	}
}

const maxDSTLength = 255

var (
	longDSTPrefix = [17]byte{'H', '2', 'C', '-', 'O', 'V', 'E', 'R', 'S', 'I', 'Z', 'E', '-', 'D', 'S', 'T', '-'}

	errorLongOutput = errors.New("requested too many bytes")
)
