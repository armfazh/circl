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

func (p *params) NewStatePriv(skSeed, pkSeed []byte) (s statePriv) {
	s.params = p
	c := cursor(make([]byte, s.Size()))
	s.state.Init(p, &c, pkSeed)
	s.PRF.Init(p, &c, skSeed, pkSeed)
	if p.isSha2 {
		s.PRF.hasher = sha256sum
	} else {
		s.PRF.hasher = shake256sum
	}
	return
}

func (s *statePriv) Size() int { return s.statePub.Size() + s.PRF.Size(s.params) }
func (s *statePriv) Clear() {
	s.PRF.Clear()
	s.statePub.Clear()
}

type statePub struct{ state }

func (p *params) NewStatePub(pkSeed []byte) (s statePub) {
	s.params = p
	c := cursor(make([]byte, s.Size()))
	s.Init(p, &c, pkSeed)
	return
}

type state struct {
	*params

	F stateF
	H stateH
	T stateT
}

func (s *state) Size() int { return s.F.Size(s.params) + s.H.Size(s.params) + s.T.Size(s.params) }
func (s *state) Init(p *params, c *cursor, pkSeed []byte) {
	s.F.Init(p, c, pkSeed)
	s.H.Init(p, c, pkSeed)
	s.T.Init(p, c, pkSeed)

	if p.isSha2 {
		s.F.hasher = sha256sum
		if p.n == 16 {
			s.H.hasher = sha256sum
			s.T.hasher = &sha2rw{Hash: sha256.New()}
		} else {
			s.H.hasher = sha512sum
			s.T.hasher = &sha2rw{Hash: sha512.New()}
		}
	} else {
		s.F.hasher = shake256sum
		s.H.hasher = shake256sum
		s.T.hasher = &sha3rw{State: sha3.NewShake256()}
	}
}

func (s *state) Clear() {
	s.F.Clear()
	s.T.Clear()
	s.H.Clear()
	s.params = nil
}

func sha256sum(out, in []byte)   { s := sha256.Sum256(in); copy(out, s[:]) }
func sha512sum(out, in []byte)   { s := sha512.Sum512(in); copy(out, s[:]) }
func shake256sum(out, in []byte) { sha3.ShakeSum256(out, in) }

type stateCommonHasher struct {
	input, output []byte
	hasher        func(out, in []byte)
	address
}

func (s *stateCommonHasher) Clear() {
	clearSlice(&s.input)
	clearSlice(&s.output)
	s.address.Clear()
}
func (s *stateCommonHasher) Size(p *params) int { return p.n + p.addressSize() }
func (s *stateCommonHasher) SumByRef() []byte   { s.hasher(s.output, s.input); return s.output }
func (s *stateCommonHasher) SumCopy(out []byte) { s.hasher(out, s.input) }

type statePRF struct{ stateCommonHasher }

func (s *statePRF) Init(p *params, cur *cursor, skSeed, pkSeed []byte) {
	c := cursor(cur.Next(s.Size(p)))
	s.output = c.Next(p.n)
	s.input = c.Rest()
	copy(c.Next(p.n), pkSeed)
	_ = c.Next(s.padSize(p))
	s.address.fromBytes(p, &c)
	copy(c.Next(p.n), skSeed)
}
func (s *statePRF) Size(p *params) int { return 2*p.n + s.padSize(p) + s.stateCommonHasher.Size(p) }
func (s *statePRF) padSize(p *params) int {
	if p.isSha2 {
		return 64 - p.n
	} else {
		return 0
	}
}

type stateF struct {
	stateCommonHasher
	msg []byte
}

func (s *stateF) Init(p *params, cur *cursor, pkSeed []byte) {
	c := cursor(cur.Next(s.Size(p)))
	s.output = c.Next(p.n)
	s.input = c.Rest()
	copy(c.Next(p.n), pkSeed)
	_ = c.Next(s.padSize(p))
	s.address.fromBytes(p, &c)
	s.msg = c.Next(p.n)
}
func (s *stateF) Clear()             { s.stateCommonHasher.Clear(); clearSlice(&s.msg) }
func (s *stateF) SetMsg(msg []byte)  { copy(s.msg, msg) }
func (s *stateF) Size(p *params) int { return 2*p.n + s.padSize(p) + s.stateCommonHasher.Size(p) }
func (s *stateF) padSize(p *params) int {
	if p.isSha2 {
		return 64 - p.n
	} else {
		return 0
	}
}

type stateH struct {
	stateCommonHasher
	msg0, msg1 []byte
}

func (s *stateH) Init(p *params, cur *cursor, pkSeed []byte) {
	c := cursor(cur.Next(s.Size(p)))
	s.output = c.Next(p.n)
	s.input = c.Rest()
	copy(c.Next(p.n), pkSeed)
	_ = c.Next(s.padSize(p))
	s.address.fromBytes(p, &c)
	s.msg0 = c.Next(p.n)
	s.msg1 = c.Next(p.n)
}
func (s *stateH) Clear()                { s.stateCommonHasher.Clear(); clearSlice(&s.msg0); clearSlice(&s.msg1) }
func (s *stateH) SetMsgs(m0, m1 []byte) { copy(s.msg0, m0); copy(s.msg1, m1) }
func (s *stateH) Size(p *params) int    { return 3*p.n + s.padSize(p) + s.stateCommonHasher.Size(p) }
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

type stateT struct {
	stateCommonHasher
	hasher
}

func (s *stateT) Init(p *params, cur *cursor, pkSeed []byte) {
	c := cursor(cur.Next(s.Size(p)))
	s.output = c.Next(p.n)
	s.input = c.Rest()
	copy(c.Next(p.n), pkSeed)
	_ = c.Next(s.padSize(p))
	s.address.fromBytes(p, &c)
}
func (s *stateT) Clear()               { s.stateCommonHasher.Clear(); s.hasher.Reset() }
func (s *stateT) Start()               { s.hasher.Reset(); _, _ = s.hasher.Write(s.input) }
func (s *stateT) AppendMsg(msg []byte) { _, _ = s.hasher.Write(msg) }
func (s *stateT) SumByRef() []byte     { s.hasher.Sum(s.output); return s.output }
func (s *stateT) SumCopy(out []byte)   { s.hasher.Sum(out) }
func (s *stateT) Size(p *params) int   { return p.n + s.padSize(p) + s.stateCommonHasher.Size(p) }
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

type hasher interface {
	io.Writer
	Reset()
	Sum([]byte)
	SumByCopy(out []byte)
}

type sha2rw struct {
	sum [sha512.Size]byte
	hash.Hash
}

func (s *sha2rw) Sum(out []byte)       { copy(out, s.Hash.Sum(s.sum[:0])) }
func (s *sha2rw) SumByCopy(out []byte) { s.Sum(out) }

type sha3rw struct{ sha3.State }

func (s *sha3rw) Sum(out []byte)       { _, _ = s.Read(out) }
func (s *sha3rw) SumByCopy(out []byte) { c := s.State.Clone(); _, _ = c.Read(out) }

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

func (p *params) NewStack(z int) (s stateStack) {
	s.sh.new(z)
	s.si.new(z + 1)
	c := cursor(make([]byte, (z+1)*p.n))
	for i := 0; i < z+1; i++ {
		s.si.push(item{uint32(i), c.Next(p.n)})
	}
	return
}
func (s *stateStack) Clear() { s.sh.clear(); s.si.clear() }

type cursor []byte

func (s *cursor) Rest() []byte { return (*s)[:] }
func (s *cursor) Next(n int) (out []byte) {
	out = (*s)[:n]
	*s = (*s)[n:]
	return
}

func clearSlice(s *[]byte) { clear(*s); *s = nil }
