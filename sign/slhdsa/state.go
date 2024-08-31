package slhdsa

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"io"

	"github.com/cloudflare/circl/internal/sha3"
)

type statePriv struct {
	statePub

	PRF statePRF
}

func (s *statePriv) size() int { return s.statePub.size() + s.PRF.size(s.params) }

func (p *params) newStatePriv(skSeed, pkSeed []byte) (s *statePriv) {
	s = new(statePriv)

	s.statePub = *p.newStatePub(pkSeed)
	c := cursor(make([]byte, s.size()))
	s.PRF.init(p, &c, skSeed, pkSeed)

	if p.isSha2 {
		s.PRF.hasher = sha256sum
	} else {
		s.PRF.hasher = shake256sum
	}

	return
}

func (s *statePriv) clear() {
	s.PRF.clear()
	s.statePub.clear()
}

type state = statePub

type statePub struct {
	*params

	F stateF
	H stateH
	T stateT
}

func (s *state) size() int {
	return s.F.size(s.params) + s.H.size(s.params) + s.T.size(s.params)
}

func (p *params) newStatePub(pkSeed []byte) (s *state) {
	s = new(state)
	s.params = p

	c := cursor(make([]byte, s.size()))
	s.F.init(p, &c, pkSeed)
	s.H.init(p, &c, pkSeed)
	s.T.init(p, &c, pkSeed)

	if p.isSha2 {
		s.F.hasher = sha256sum
		if p.n == 16 {
			s.H.hasher = sha256sum
			s.T.rw = &sha2rw{Hash: sha256.New()}
		} else {
			s.H.hasher = sha512sum
			s.T.rw = &sha2rw{Hash: sha512.New()}
		}
	} else {
		s.F.hasher = shake256sum
		s.H.hasher = shake256sum
		s.T.rw = &sha3rw{State: sha3.NewShake256()}
	}

	return
}

func (s *state) clear() {
	s.F.clear()
	s.T.clear()
	s.H.clear()
	s.params = nil
}

func sha256sum(out, in []byte)   { s := sha256.Sum256(in); copy(out, s[:]) }
func sha512sum(out, in []byte)   { s := sha512.Sum512(in); copy(out, s[:]) }
func shake256sum(out, in []byte) { sha3.ShakeSum256(out, in) }

type rw interface {
	io.Writer
	Reset()
	Sum([]byte)
}

type sha2rw struct {
	sum [sha512.Size]byte
	hash.Hash
}

func (s *sha2rw) Sum(out []byte) { copy(out, s.Hash.Sum(s.sum[:0])) }

type sha3rw struct{ sha3.State }

func (s *sha3rw) Sum(out []byte) { _, _ = s.Read(out) }

type stateCommonHasher struct {
	input, output []byte
	hasher        func(out, in []byte)
	address
}

func (s *stateCommonHasher) clear() {
	clearSlice(&s.input)
	clearSlice(&s.output)
	s.address.clean()
}
func (s *stateCommonHasher) size(p *params) int   { return p.n + p.addressSize() }
func (s *stateCommonHasher) SetAddress(a address) { copy(s.address.b, a.b); s.address.o = a.o }
func (s *stateCommonHasher) SumByRef() []byte     { s.SumCopy(s.output); return s.output }
func (s *stateCommonHasher) SumCopy(out []byte)   { s.hasher(out, s.input) }

type statePRF struct{ stateCommonHasher }

func (s *statePRF) size(p *params) int { return 2*p.n + s.padSize(p) + s.stateCommonHasher.size(p) }
func (s *statePRF) padSize(p *params) int {
	if p.isSha2 {
		return 64 - p.n
	} else {
		return 0
	}
}
func (s *statePRF) init(p *params, cc *cursor, skSeed, pkSeed []byte) {
	c := cursor(cc.Next(s.size(p)))
	s.output = c.Next(p.n)
	s.input = c.Rest()
	copy(c.Next(p.n), pkSeed)
	_ = c.Next(s.padSize(p))
	s.address.fromBytes(p, &c)
	copy(c.Next(p.n), skSeed)
}

type stateF struct {
	stateCommonHasher
	msg []byte
}

func (s *stateF) size(p *params) int { return 2*p.n + s.padSize(p) + s.stateCommonHasher.size(p) }
func (s *stateF) padSize(p *params) int {
	if p.isSha2 {
		return 64 - p.n
	} else {
		return 0
	}
}
func (s *stateF) init(p *params, cc *cursor, pkSeed []byte) {
	c := cursor(cc.Next(s.size(p)))
	s.output = c.Next(p.n)
	s.input = c.Rest()
	copy(c.Next(p.n), pkSeed)
	_ = c.Next(s.padSize(p))
	s.address.fromBytes(p, &c)
	s.msg = c.Next(p.n)
}
func (s *stateF) clear()            { s.stateCommonHasher.clear(); clearSlice(&s.msg) }
func (s *stateF) SetMsg(msg []byte) { copy(s.msg, msg) }

type stateH struct {
	stateCommonHasher
	msg0, msg1 []byte
}

func (s *stateH) size(p *params) int { return 3*p.n + s.padSize(p) + s.stateCommonHasher.size(p) }
func (s *stateH) padSize(p *params) int {
	if p.isSha2 {
		if p.n == 16 {
			return 64 - p.n
		} else {
			return 128 - p.n
		}
	} else {
		return 0
	}
}
func (s *stateH) init(p *params, cc *cursor, pkSeed []byte) {
	c := cursor(cc.Next(s.size(p)))
	s.output = c.Next(p.n)
	s.input = c.Rest()
	copy(c.Next(p.n), pkSeed)
	_ = c.Next(s.padSize(p))
	s.address.fromBytes(p, &c)
	s.msg0 = c.Next(p.n)
	s.msg1 = c.Next(p.n)
}
func (s *stateH) clear()                { s.stateCommonHasher.clear(); clearSlice(&s.msg0); clearSlice(&s.msg1) }
func (s *stateH) SetMsgs(m0, m1 []byte) { copy(s.msg0, m0); copy(s.msg1, m1) }

type stateT struct {
	stateCommonHasher
	rw
}

func (s *stateT) size(p *params) int { return p.n + s.padSize(p) + s.stateCommonHasher.size(p) }
func (s *stateT) padSize(p *params) int {
	if p.isSha2 {
		if p.n == 16 {
			return 64 - p.n
		} else {
			return 128 - p.n
		}
	} else {
		return 0
	}
}
func (s *stateT) init(p *params, cc *cursor, pkSeed []byte) {
	c := cursor(cc.Next(s.size(p)))
	s.output = c.Next(p.n)
	s.input = c.Rest()
	copy(c.Next(p.n), pkSeed)
	_ = c.Next(s.padSize(p))
	s.address.fromBytes(p, &c)
}

func (s *stateT) Start()               { s.Reset(); _, _ = s.Write(s.input) }
func (s *stateT) AppendMsg(msg []byte) { _, _ = s.Write(msg) }
func (s *stateT) SumByRef() []byte     { s.SumCopy(s.output); return s.output }
func (s *stateT) SumCopy(out []byte)   { s.Sum(out) }

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
func (s *stack) clear() {
	for i := range *s {
		clearSlice(&(*s)[i].node)
	}
	clear((*s)[:])
	*s = nil
}

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
