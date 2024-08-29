package slhdsa

import (
	"crypto"
	"crypto/sha256"
	"crypto/sha512"

	"github.com/cloudflare/circl/internal/sha3"
)

type state struct {
	*params
	hasher

	prf stateHasherPRF
	f   stateHasherF
	t   stateHasherT
	h   stateHasherH
}

func (p *params) newState() (s *state) {
	s = new(state)
	s.params = p

	if p.isSha2 {
		if p.n == 16 {
			s.hasher = &sha2Fn{
				hmacFn: crypto.SHA256,
				state:  sha256.New(),
			}
		} else {
			s.hasher = &sha2Fn{
				hmacFn: crypto.SHA512,
				state:  sha512.New(),
			}
		}
	} else {
		s.hasher = &shakeFn{sha3.NewShake256()}
	}

	s.prf.init(p)
	s.f.init(p)
	s.t.init(p)
	s.h.init(p)

	return
}

func (s *state) clear() {
	s.prf.clear()
	s.f.clear()
	s.t.clear()
	s.h.clear()
	s.hasher.clear()
	s.hasher = nil
	s.params = nil
}

type stateCommonHasher struct {
	rw
	input  []byte
	output []byte
	pkSeed []byte
	address
}

func (s *stateCommonHasher) SetPkSeed(pkSeed []byte) { copy(s.pkSeed, pkSeed) }
func (s *stateCommonHasher) SetAddress(a *address)   { copy(s.address.b, a.b); s.address.o = a.o }
func (s *stateCommonHasher) SumByRef() []byte        { s.SumCopy(s.output); return s.output }
func (s *stateCommonHasher) SumCopy(out []byte) {
	s.rw.Reset()
	s.rw.Write(s.input)
	s.rw.Sum(out)
}
func (s *stateCommonHasher) clear() {
	clearSlice(&s.output)
	clearSlice(&s.input)
	clearSlice(&s.pkSeed)
	s.address = address{}
	s.rw.Reset()
	s.rw = nil
}

type stateHasherPRF struct {
	stateCommonHasher
	skSeed []byte
}

func (s *stateHasherPRF) init(p *params) {
	addrOffset, addrLen := p.addressParams()
	padLen := 0
	if p.isSha2 {
		padLen = 64 - p.n
	}

	c := cursor(make([]byte, 3*p.n+padLen+addrLen))

	s.output = c.Next(p.n)
	s.input = c.Rest()
	s.pkSeed = c.Next(p.n)
	_ = c.Next(padLen)
	s.address.o = addrOffset
	s.address.b = c.Next(addrLen)
	s.skSeed = c.Next(p.n)

	if p.isSha2 {
		s.rw = &sha2rw{state: sha256.New()}
	} else {
		s.rw = &sha3rw{state: sha3.NewShake256()}
	}
}

func (s *stateHasherPRF) SetSkSeed(skSeed []byte) { copy(s.skSeed, skSeed) }
func (s *stateHasherPRF) clear()                  { s.stateCommonHasher.clear(); clearSlice(&s.skSeed) }

type stateHasherF struct {
	stateCommonHasher
	msg []byte
}

func (s *stateHasherF) init(p *params) {
	addrOffset, addrLen := p.addressParams()
	padLen := 0
	if p.isSha2 {
		padLen = 64 - p.n
	}

	c := cursor(make([]byte, 3*p.n+padLen+addrLen))
	s.output = c.Next(p.n)
	s.input = c.Rest()
	s.pkSeed = c.Next(p.n)
	_ = c.Next(padLen)
	s.address.o = addrOffset
	s.address.b = c.Next(addrLen)
	s.msg = c.Next(p.n)

	if p.isSha2 {
		s.rw = &sha2rw{state: sha256.New()}
	} else {
		s.rw = &sha3rw{state: sha3.NewShake256()}
	}
}

func (s *stateHasherF) SetMsg(msg []byte) { copy(s.msg, msg) }
func (s *stateHasherF) clear()            { s.stateCommonHasher.clear(); clearSlice(&s.msg) }

type stateHasherH struct {
	stateCommonHasher
	msg0 []byte
	msg1 []byte
}

func (s *stateHasherH) init(p *params) {
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
	s.output = c.Next(p.n)
	s.input = c.Rest()
	s.pkSeed = c.Next(p.n)
	_ = c.Next(padLen)
	s.address.o = addrOffset
	s.address.b = c.Next(addrLen)
	s.msg0 = c.Next(p.n)
	s.msg1 = c.Next(p.n)

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

func (s *stateHasherH) SetMsgs(msg0, msg1 []byte) { copy(s.msg0, msg0); copy(s.msg1, msg1) }
func (s *stateHasherH) clear()                    { s.stateCommonHasher.clear(); clearSlice(&s.msg0); clearSlice(&s.msg1) }

type stateHasherT struct{ stateCommonHasher }

func (s *stateHasherT) init(p *params) {
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
	s.output = c.Next(p.n)
	s.input = c.Rest()
	s.pkSeed = c.Next(p.n)
	_ = c.Next(padLen)
	s.address.o = addrOffset
	s.address.b = c.Next(addrLen)

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
func (s *stateHasherT) Start()               { s.rw.Reset(); s.rw.Write(s.input) }
func (s *stateHasherT) AppendMsg(msg []byte) { s.rw.Write(msg) }
func (s *stateHasherT) SumByRef() []byte     { s.SumCopy(s.output); return s.output }
func (s *stateHasherT) SumCopy(out []byte)   { s.rw.Sum(out) }

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
