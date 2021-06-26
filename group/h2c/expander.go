// Package h2c provides methods for hash to curve functions.
package h2c

import (
	"crypto"
	_ "crypto/sha256" // to link libraries
	_ "crypto/sha512" // to link libraries
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"math"

	"github.com/cloudflare/circl/xof"
)

// Expander allows to derive bytes from a slice input. This is described in
// hash to curve IETF draft.
// See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-5.4
// for more details.
type Expander interface {
	// Reset cleans the internal state to allow writing another input. Discards
	// any input written previously.
	Reset()
	// Use writer to consume the input of the expander. Panics if it is invoked
	// after Expand function was called.
	io.Writer
	// Expand fills the slice with bytes produced by the expander. Panics if
	// the output's length is larger than an implementation-dependent limit.
	Expand([]byte)
}

// ExpanderMD is based on a Merkle-Damgård hash function.
type ExpanderMD struct {
	h         crypto.Hash
	dst       []byte
	state     hash.Hash
	didExpand bool
}

// NewExpanderMD returns an Expander based on a Merkle-Damgård hash function.
// The dst is a domain separation string.
func NewExpanderMD(h crypto.Hash, dst []byte) *ExpanderMD {
	e := &ExpanderMD{h, dst, nil, false}
	e.Reset()
	return e
}

func (e *ExpanderMD) Reset() {
	e.didExpand = false
	if e.state == nil {
		e.state = e.h.New()
	} else {
		e.state.Reset()
	}

	// preambleB0
	zPad := make([]byte, e.state.BlockSize())
	_, _ = e.state.Write(zPad)
}

func (e *ExpanderMD) Write(input []byte) (int, error) {
	if e.didExpand {
		panic(errorExpander)
	}
	return e.state.Write(input)
}

// Expand panics if the length of the output is longer than 255 times the
// blocksize of the hash function.
func (e *ExpanderMD) Expand(output []byte) {
	bInBytes := e.h.Size()
	numBlocksEll := (len(output) + bInBytes - 1) / bInBytes
	if numBlocksEll > 255 {
		panic(errorLongOutput)
	}

	if e.didExpand {
		panic(errorExpander)
	}

	e.didExpand = true
	dstPrime := e.calcDSTPrime()
	libStr := [3]byte{}
	binary.BigEndian.PutUint16(libStr[:2], uint16(len(output)))
	_, _ = e.state.Write(libStr[:])
	_, _ = e.state.Write(dstPrime)
	b0 := e.state.Sum(nil)

	bi := make([]byte, len(b0))
	off := 0
	for i := 1; i <= numBlocksEll; i++ {
		for j := range b0 {
			bi[j] ^= b0[j]
		}
		e.state.Reset()
		_, _ = e.state.Write(bi)
		_, _ = e.state.Write([]byte{byte(i)})
		_, _ = e.state.Write(dstPrime)
		bi = e.state.Sum(nil)
		off += copy(output[off:], bi)
	}
}

func (e *ExpanderMD) calcDSTPrime() []byte {
	var dstPrime []byte
	if l := len(e.dst); l > maxDSTLength {
		e.state = e.h.New()
		_, _ = e.state.Write(longDSTPrefix[:])
		_, _ = e.state.Write(e.dst)
		dstPrime = e.state.Sum(nil)
	} else {
		dstPrime = make([]byte, l, l+1)
		copy(dstPrime, e.dst)
	}
	return append(dstPrime, byte(len(dstPrime)))
}

// ExpanderXOF is based on an extendable output function.
type ExpanderXOF struct {
	id        xof.ID
	kSecLevel uint
	dst       []byte
	state     xof.XOF
	didExpand bool
}

// NewExpanderXOF returns an Expander based on an extendable output function.
// The kSecLevel parameter is the target security level in bits, and dst is
// a domain separation string.
func NewExpanderXOF(id xof.ID, kSecLevel uint, dst []byte) *ExpanderXOF {
	e := &ExpanderXOF{id, kSecLevel, dst, nil, false}
	e.Reset()
	return e
}

func (e *ExpanderXOF) Reset() {
	e.didExpand = false
	if e.state == nil {
		e.state = e.id.New()
	} else {
		e.state.Reset()
	}
}

func (e *ExpanderXOF) Write(input []byte) (int, error) {
	if e.didExpand {
		panic(errorExpander)
	}
	return e.state.Write(input)
}

// Expand panics if output's length is longer than 2^16 bytes.
func (e *ExpanderXOF) Expand(output []byte) {
	if len(output) >= math.MaxUint16 {
		panic(errorLongOutput)
	}
	if e.didExpand {
		panic(errorExpander)
	}

	e.didExpand = true
	dstPrime := e.calcDSTPrime()
	bLen := [2]byte{}
	binary.BigEndian.PutUint16(bLen[:], uint16(len(output)))
	_, _ = e.state.Write(bLen[:])
	_, _ = e.state.Write(dstPrime)
	_, _ = io.ReadFull(e.state, output)
}

func (e *ExpanderXOF) calcDSTPrime() []byte {
	var dstPrime []byte
	if l := len(e.dst); l > maxDSTLength {
		e.state = e.id.New()
		_, _ = e.state.Write(longDSTPrefix[:])
		_, _ = e.state.Write(e.dst)
		max := ((2 * e.kSecLevel) + 7) / 8
		dstPrime = make([]byte, max, max+1)
		_, _ = io.ReadFull(e.state, dstPrime)
	} else {
		dstPrime = make([]byte, l, l+1)
		copy(dstPrime, e.dst)
	}
	return append(dstPrime, byte(len(dstPrime)))
}

const maxDSTLength = 255

var (
	longDSTPrefix = [17]byte{'H', '2', 'C', '-', 'O', 'V', 'E', 'R', 'S', 'I', 'Z', 'E', '-', 'D', 'S', 'T', '-'}

	errorExpander   = errors.New("expand function already called, reset the expander")
	errorLongOutput = errors.New("requested too many bytes")
)
