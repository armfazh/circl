package slhdsa

import (
	"crypto/sha256"
	"crypto/sha512"

	"github.com/cloudflare/circl/internal/sha3"
)

type state struct {
	*params

	entire []byte

	prf stateHasherPRF
	f   stateHasherF
	t   stateHasherT
	h   stateHasherH

	pkSeed []byte
	skSeed []byte

	rw_F_PRF rw
	rw_H     rw
	rw_T     rw
}

func (p *params) newState(skSeed, pkSeed []byte) (s *state) {
	s = new(state)
	s.params = p

	s.entire = make([]byte, 2*p.n)
	c := cursor(s.entire)

	s.skSeed = c.Next(p.n)
	copy(s.skSeed, skSeed)

	s.pkSeed = c.Next(p.n)
	copy(s.pkSeed, pkSeed)

	if p.isSha2 {
		s256 := sha2rw{state: sha256.New()}
		s.rw_F_PRF = &s256
		if p.n == 16 {
			s.rw_H = &s256
			s.rw_T = &sha2rw{state: sha256.New()}
		} else {
			s.rw_H = &sha2rw{state: sha512.New()}
			s.rw_T = &sha2rw{state: sha512.New()}
		}
	} else {
		shake256 := sha3rw{sha3.NewShake256()}
		s.rw_F_PRF = &shake256
		s.rw_H = &shake256
		s.rw_T = &sha3rw{sha3.NewShake256()}
	}

	s.prf_init()
	s.f_init()
	s.t_init()
	s.h_init()
	return
}

func (s *state) clear() {
	s.prf.clear()
	s.f.clear()
	s.t.clear()
	s.h.clear()

	clearSlice(&s.skSeed)
	clearSlice(&s.pkSeed)
	s.rw_F_PRF.Reset()
	s.rw_H.Reset()
	s.rw_T.Reset()

	s.params = nil
}

type stateCommonHasher struct {
	input  []byte
	output []byte
	address
}

func (s *stateCommonHasher) SetAddress(a *address) { copy(s.address.b, a.b); s.address.o = a.o }
func (s *stateCommonHasher) clear() {
	clearSlice(&s.input)
	clearSlice(&s.output)
	clearSlice(&s.address.b)
	s.address = address{}
}

type stateHasherPRF struct{ stateCommonHasher }

func (s *state) prf_init() {
	p := s.params
	addrOffset, addrLen := p.addressParams()
	padLen := 0
	if p.isSha2 {
		padLen = 64 - p.n
	}

	c := cursor(make([]byte, 3*p.n+padLen+addrLen))

	s.prf.output = c.Next(p.n)
	s.prf.input = c.Rest()
	copy(c.Next(p.n), s.pkSeed)
	_ = c.Next(padLen)
	s.prf.address.o = addrOffset
	s.prf.address.b = c.Next(addrLen)
	copy(c.Next(p.n), s.skSeed)
}
func (s *state) PRF_SumByRef() []byte { s.PRF_SumCopy(s.prf.output); return s.prf.output }
func (s *state) PRF_SumCopy(out []byte) {
	s.rw_F_PRF.Reset()
	s.rw_F_PRF.Write(s.prf.input)
	s.rw_F_PRF.Sum(out)
}

type stateHasherF struct {
	stateCommonHasher
	msg []byte
}

func (s *state) f_init() {
	p := s.params
	addrOffset, addrLen := p.addressParams()
	padLen := 0
	if p.isSha2 {
		padLen = 64 - p.n
	}

	c := cursor(make([]byte, 3*p.n+padLen+addrLen))
	s.f.output = c.Next(p.n)
	s.f.input = c.Rest()
	copy(c.Next(p.n), s.pkSeed)
	_ = c.Next(padLen)
	s.f.address.o = addrOffset
	s.f.address.b = c.Next(addrLen)
	s.f.msg = c.Next(p.n)
}

func (s *stateHasherF) SetMsg(msg []byte) { copy(s.msg, msg) }
func (s *stateHasherF) clear()            { s.stateCommonHasher.clear(); clearSlice(&s.msg) }
func (s *state) F_SumByRef() []byte       { s.F_SumCopy(s.f.output); return s.f.output }
func (s *state) F_SumCopy(out []byte) {
	s.rw_F_PRF.Reset()
	s.rw_F_PRF.Write(s.f.input)
	s.rw_F_PRF.Sum(out)
}

type stateHasherH struct {
	stateCommonHasher
	msg0 []byte
	msg1 []byte
}

func (s *state) h_init() {
	p := s.params
	addrOffset, addrLen := p.addressParams()
	padLen := 0
	if p.isSha2 {
		if p.n == 16 {
			padLen = 64 - p.n
		} else {
			padLen = 128 - p.n
		}
	}

	c := cursor(make([]byte, 4*p.n+padLen+addrLen))
	s.h.output = c.Next(p.n)
	s.h.input = c.Rest()
	copy(c.Next(p.n), s.pkSeed)
	_ = c.Next(padLen)
	s.h.address.o = addrOffset
	s.h.address.b = c.Next(addrLen)
	s.h.msg0 = c.Next(p.n)
	s.h.msg1 = c.Next(p.n)
}

func (s *stateHasherH) SetMsgs(msg0, msg1 []byte) { copy(s.msg0, msg0); copy(s.msg1, msg1) }
func (s *stateHasherH) clear()                    { s.stateCommonHasher.clear(); clearSlice(&s.msg0); clearSlice(&s.msg1) }
func (s *state) H_SumByRef() []byte               { s.H_SumCopy(s.h.output); return s.h.output }
func (s *state) H_SumCopy(out []byte) {
	s.rw_H.Reset()
	s.rw_H.Write(s.h.input)
	s.rw_H.Sum(out)
}

type stateHasherT struct{ stateCommonHasher }

func (s *state) t_init() {
	p := s.params
	addrOffset, addrLen := p.addressParams()
	padLen := 0
	if p.isSha2 {
		if p.n == 16 {
			padLen = 64 - p.n
		} else {
			padLen = 128 - p.n
		}
	}

	c := cursor(make([]byte, 2*p.n+padLen+addrLen))
	s.t.output = c.Next(p.n)
	s.t.input = c.Rest()
	copy(c.Next(p.n), s.pkSeed)
	_ = c.Next(padLen)
	s.t.address.o = addrOffset
	s.t.address.b = c.Next(addrLen)
}
func (s *state) T_Start()               { s.rw_T.Reset(); s.rw_T.Write(s.t.input) }
func (s *state) T_AppendMsg(msg []byte) { s.rw_T.Write(msg) }
func (s *state) T_SumByRef() []byte     { s.T_SumCopy(s.t.output); return s.t.output }
func (s *state) T_SumCopy(out []byte)   { s.rw_T.Sum(out) }

type stack []item

func (s *stack) new(n int)     { *s = make([]item, 0, n) }
func (s *stack) top() item     { return (*s)[len(*s)-1] }
func (s *stack) isEmpty() bool { return len(*s) == 0 }
func (s *stack) push(v item)   { *s = append(*s, v) }
func (s *stack) pop() (v item) {
	last := len(*s) - 1
	if last >= 0 {
		v = (*s)[last]
		*s = (*s)[:last]
	}
	return
}
func (s *stack) clear() { clear((*s)[:]); *s = nil }

type (
	item struct {
		z    uint32
		node []byte
	}
)

type stateStack struct {
	sh stack
	si stack
}

func (s *stateStack) clear() { s.sh.clear(); s.si.clear() }

func (p *params) newStack(z int) (s stateStack) {
	s.sh.new(z)
	s.si.new(z + 1)
	c := cursor(make([]byte, (z+1)*p.n))
	for i := 0; i < z+1; i++ {
		s.si.push(item{uint32(i), c.Next(p.n)})
	}

	return
}

type cursor []byte

func (s *cursor) Rest() []byte { return (*s)[:] }
func (s *cursor) Next(n int) (out []byte) {
	out = (*s)[:n]
	*s = (*s)[n:]
	return
}

func clearSlice(s *[]byte) { clear(*s); *s = nil }
