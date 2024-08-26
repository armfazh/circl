package slhdsa

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"

	"github.com/cloudflare/circl/internal/sha3"
)

type state struct {
	*params
	hasher

	prf statePRF
	f   stateF
	t   stateT
}

type statePRF struct {
	rw
	input  []byte
	output []byte

	pkSeed  []byte
	address []byte
	skSeed  []byte
}

func (s *statePRF) init(p *params) {
	addrLen := 32
	padLen := 0
	if p.isSha2 {
		addrLen = 22
		padLen = 64 - p.n
	}

	s.output = make([]byte, p.n)
	s.input = make([]byte, 2*p.n+padLen+addrLen)
	buf := bytes.NewBuffer(s.input)

	s.pkSeed = buf.Next(p.n)
	_ = buf.Next(padLen)
	s.address = buf.Next(addrLen)
	s.skSeed = buf.Next(p.n)

	if p.isSha2 {
		s.rw = &sha2rw{state: sha256.New()}
	} else {
		s.rw = &sha3rw{state: sha3.NewShake256()}
	}
}

func (s *statePRF) SetPkSeed(pkSeed []byte) { copy(s.pkSeed, pkSeed) }
func (s *statePRF) SetAddress(a *address)   { copy(s.address, a.Bytes()) }
func (s *statePRF) SetSkSeed(skSeed []byte) { copy(s.skSeed, skSeed) }
func (s *statePRF) SumByRef() []byte        { s.SumCopy(s.output); return s.output }
func (s *statePRF) SumCopy(out []byte) {
	s.rw.Reset()
	s.rw.Write(s.input)
	s.rw.Sum(out)
}

type stateF struct {
	rw
	input  []byte
	output []byte

	pkSeed  []byte
	address []byte
	msg     []byte
}

func (s *stateF) init(p *params) {
	addrLen := 32
	padLen := 0
	if p.isSha2 {
		addrLen = 22
		padLen = 64 - p.n
	}

	s.output = make([]byte, p.n)
	s.input = make([]byte, 2*p.n+padLen+addrLen)
	buf := bytes.NewBuffer(s.input)

	s.pkSeed = buf.Next(p.n)
	_ = buf.Next(padLen)
	s.address = buf.Next(addrLen)
	s.msg = buf.Next(p.n)

	if p.isSha2 {
		s.rw = &sha2rw{state: sha256.New()}
	} else {
		s.rw = &sha3rw{state: sha3.NewShake256()}
	}
}
func (s *stateF) SetPkSeed(pkSeed []byte) { copy(s.pkSeed, pkSeed) }
func (s *stateF) SetAddress(a *address)   { copy(s.address, a.Bytes()) }
func (s *stateF) SetMsg(msg []byte)       { copy(s.msg, msg) }
func (s *stateF) SumByRef() []byte        { s.SumCopy(s.output); return s.output }
func (s *stateF) SumCopy(out []byte) {
	s.rw.Reset()
	s.rw.Write(s.input)
	s.rw.Sum(out)
}

type stateT struct {
	rw
	input  []byte
	output []byte

	pkSeed  []byte
	address []byte
}

func (s *stateT) init(p *params) {
	addrLen := 32
	padLen := 0
	if p.isSha2 {
		addrLen = 22
		if p.n == 16 {
			padLen = 64 - p.n
		} else {
			padLen = 128 - p.n
		}
	}

	s.output = make([]byte, p.n)
	s.input = make([]byte, p.n+padLen+addrLen)
	buf := bytes.NewBuffer(s.input)

	s.pkSeed = buf.Next(p.n)
	_ = buf.Next(padLen)
	s.address = buf.Next(addrLen)

	if p.isSha2 {
		if p.n == 16 {
			s.rw = &sha2rw{state: sha256.New()}
		} else {
			s.rw = &sha2rw{state: sha512.New()}
		}
	} else {
		s.rw = &sha3rw{state: sha3.NewShake256()}
	}
}
func (s *stateT) SetPkSeed(pkSeed []byte) { copy(s.pkSeed, pkSeed) }
func (s *stateT) SetAddress(a *address)   { copy(s.address, a.Bytes()) }
func (s *stateT) Start()                  { s.rw.Reset(); s.rw.Write(s.input) }
func (s *stateT) AppendMsg(msg []byte)    { s.rw.Write(msg) }
func (s *stateT) SumByRef() []byte        { s.SumCopy(s.output); return s.output }
func (s *stateT) SumCopy(out []byte)      { s.rw.Sum(out) }
