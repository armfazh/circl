package group

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"errors"
	"hash"
	"io"

	"github.com/cloudflare/circl/xof"
)

const maxDSTLength = 255

var longDSTPrefix = [17]byte{'H', '2', 'C', '-', 'O', 'V', 'E', 'R', 'S', 'I', 'Z', 'E', '-', 'D', 'S', 'T', '-'}

type Expander interface {
	io.Writer
	io.Reader
	Reset()
}

type ExpanderXMD struct {
	h         crypto.Hash
	state     hash.Hash
	dst       []byte
	b0        []byte
	bi        []byte
	capacity  uint16
	consumed  uint16
	bufOut    *bytes.Buffer
	isReading bool
}

// NewExpanderMD returns a hash function based on a Merkle-Damgård hash function.
func NewExpanderMD(h crypto.Hash, dst []byte, capacity uint16) (*ExpanderXMD, error) {
	bInBytes := h.Size()
	if numBlocksEll := (int(capacity) + bInBytes - 1) / bInBytes; numBlocksEll > 255 {
		return nil, errors.New("capacity too big")
	}

	e := &ExpanderXMD{
		h:        h,
		capacity: capacity,
	}
	e.calcDSTPrime(dst)
	e.Reset()
	return e, nil
}

func (e *ExpanderXMD) Reset() {
	e.isReading = false
	e.b0 = nil
	e.bi = nil
	e.bufOut = nil
	e.consumed = 0
	if e.state == nil {
		e.state = e.h.New()
	} else {
		e.state.Reset()
	}

	// preambleB0
	zPad := make([]byte, e.state.BlockSize())
	_, _ = e.state.Write(zPad)
}

func (e *ExpanderXMD) Write(input []byte) (int, error) {
	if e.isReading {
		panic("expander is in reading mode")
	}
	return e.state.Write(input)
}

func (e *ExpanderXMD) calcB0() error {
	libStr := [3]byte{}
	binary.BigEndian.PutUint16(libStr[:2], e.capacity)
	if _, err := e.state.Write(libStr[:]); err != nil {
		return err
	}
	if _, err := e.state.Write(e.dst); err != nil {
		return err
	}
	e.b0 = e.state.Sum(nil)
	e.bi = make([]byte, len(e.b0))
	e.bufOut = bytes.NewBuffer(nil)
	return nil
}

func (e *ExpanderXMD) newBlock() {
	blockNum := 1 + e.consumed/uint16(e.h.Size())
	for j := range e.bi {
		e.bi[j] ^= e.b0[j]
	}
	e.state.Reset()
	_, _ = e.state.Write(e.bi)
	_, _ = e.state.Write([]byte{byte(blockNum)})
	_, _ = e.state.Write(e.dst)
	e.bi = e.state.Sum(nil)
	e.bufOut.Write(e.bi)
}

func (e *ExpanderXMD) Read(output []byte) (int, error) {
	e.isReading = true

	if e.b0 == nil {
		err := e.calcB0()
		if err != nil {
			return 0, err
		}
	}

	off := 0
	reader := &io.LimitedReader{R: e.bufOut, N: int64(e.capacity - e.consumed)}
	for {
		n, err := io.ReadFull(reader, output[off:])
		e.consumed += uint16(n)
		off += n

		if err != nil && e.consumed < e.capacity {
			e.newBlock()
		} else if e.consumed == e.capacity {
			return off, io.EOF
		} else {
			return off, err
		}
	}
}

func (e *ExpanderXMD) calcDSTPrime(dst []byte) {
	var dstPrime []byte
	if l := len(dst); l > maxDSTLength {
		e.state = e.h.New()
		_, _ = e.state.Write(longDSTPrefix[:])
		_, _ = e.state.Write(dst)
		dstPrime = e.state.Sum(nil)
	} else {
		dstPrime = make([]byte, l, l+1)
		copy(dstPrime, dst)
	}
	e.dst = append(dstPrime, byte(len(dstPrime)))
}

func (e *ExpanderXMD) Expand(in []byte, n uint) []byte {
	H := e.h.New()
	bLen := uint(H.Size())
	ell := (n + (bLen - 1)) / bLen
	if ell > 255 {
		panic("too big")
	}

	zPad := make([]byte, H.BlockSize())
	libStr := []byte{0, 0}
	libStr[0] = byte((n >> 8) & 0xFF)
	libStr[1] = byte(n & 0xFF)

	H.Reset()
	_, _ = H.Write(zPad)
	_, _ = H.Write(in)
	_, _ = H.Write(libStr)
	_, _ = H.Write([]byte{0})
	_, _ = H.Write(e.dst)
	b0 := H.Sum(nil)

	H.Reset()
	_, _ = H.Write(b0)
	_, _ = H.Write([]byte{1})
	_, _ = H.Write(e.dst)
	bi := H.Sum(nil)
	pseudo := append([]byte{}, bi...)
	for i := uint(2); i <= ell; i++ {
		H.Reset()
		for i := range b0 {
			bi[i] ^= b0[i]
		}
		_, _ = H.Write(bi)
		_, _ = H.Write([]byte{byte(i)})
		_, _ = H.Write(e.dst)
		bi = H.Sum(nil)
		pseudo = append(pseudo, bi...)
	}
	return pseudo[0:n]
}

type ExpanderXOF struct {
	id              xof.ID
	state           xof.XOF
	dst             []byte
	capacity        uint16
	consumed        uint16
	isFirstReadDone bool
	isReading       bool
}

// NewExpanderXOF returns an expander based on a extendable output function.
// The k is the target security level in bits, and dst is a domain separation
// string.
func NewExpanderXOF(id xof.ID, k uint, dst []byte, capacity uint16) (*ExpanderXOF, error) {
	e := &ExpanderXOF{id: id, capacity: capacity}
	e.calcDSTPrime(dst, k)
	e.Reset()
	return e, nil
}

func (e *ExpanderXOF) Reset() {
	e.isReading = false
	e.isFirstReadDone = false
	e.consumed = 0
	if e.state == nil {
		e.state = e.id.New()
	} else {
		e.state.Reset()
	}
}
func (e *ExpanderXOF) Write(input []byte) (int, error) {
	if e.isReading {
		panic("expander is in reading mode")
	}
	return e.state.Write(input)
}
func (e *ExpanderXOF) Read(output []byte) (int, error) {
	e.isReading = true

	if !e.isFirstReadDone {
		bLen := [2]byte{}
		binary.BigEndian.PutUint16(bLen[:], e.capacity)
		if _, err := e.state.Write(bLen[:]); err != nil {
			return 0, err
		}
		if _, err := e.state.Write(e.dst); err != nil {
			return 0, err
		}
		e.isFirstReadDone = true
	}

	off := 0
	reader := &io.LimitedReader{R: e.state, N: int64(e.capacity - e.consumed)}
	for {
		n, err := io.ReadFull(reader, output[off:])
		e.consumed += uint16(n)
		off += n

		if e.consumed == e.capacity {
			return off, io.EOF
		} else {
			return off, err
		}
	}
}

func (e *ExpanderXOF) Expand(in []byte, n uint) []byte {
	bLen := []byte{0, 0}
	bLen[0] = byte((n >> 8) & 0xFF)
	bLen[1] = byte(n & 0xFF)
	pseudo := make([]byte, n)

	H := e.id.New()
	_, _ = H.Write(in)
	_, _ = H.Write(bLen)
	_, _ = H.Write(e.dst)
	_, err := io.ReadFull(H, pseudo)
	if err != nil {
		panic(err)
	}
	return pseudo
}

func (e *ExpanderXOF) calcDSTPrime(dst []byte, k uint) {
	var dstPrime []byte
	if l := len(dst); l > maxDSTLength {
		e.state = e.id.New()
		_, _ = e.state.Write(longDSTPrefix[:])
		_, _ = e.state.Write(dst)
		dstPrime = make([]byte, ((2*k)+7)/8)
		_, _ = io.ReadFull(e.state, dstPrime)
	} else {
		dstPrime = make([]byte, l, l+1)
		copy(dstPrime, dst)
	}
	e.dst = append(dstPrime, byte(len(dstPrime)))
}
