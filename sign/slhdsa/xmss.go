package slhdsa

import (
	"bytes"

	"golang.org/x/crypto/cryptobyte"
)

type (
	xmssPublicKey []byte // n bytes
	xmssSignature struct {
		wotsSig  wotsSignature // len*n bytes
		authPath [][]byte      // h*n bytes
	}
)

func (xs *xmssSignature) Marshal(b *cryptobyte.Builder) (err error) {
	b.AddValue(&xs.wotsSig)
	for i := range xs.authPath {
		b.AddBytes(xs.authPath[i])
	}
	return
}

func (xs *xmssSignature) Unmarshal(p *params, str *cryptobyte.String) bool {
	if !xs.wotsSig.Unmarshal(p, str) {
		return false
	}

	xs.authPath = make([][]byte, p.hPrime)
	buf := make([]byte, p.n*p.hPrime)
	for i := 0; i < p.hPrime; i++ {
		xs.authPath[i] = buf[:p.n]
		if !str.CopyBytes(xs.authPath[i]) {
			return false
		}
		buf = buf[p.n:]
	}

	return true
}

func (s *state) xmssNode(skSeed []byte, i, z uint32, pkSeed []byte, addr *address) (node []byte) {
	return s.xmssNodeRec(skSeed, i, z, pkSeed, addr)
}

func (s *state) xmssNodeRec(skSeed []byte, i, z uint32, pkSeed []byte, addr *address) (node []byte) {
	if !(z <= uint32(s.hPrime) && i < (1<<(uint32(s.hPrime)-z))) {
		panic(ErrNode)
	}

	if z == 0 {
		addr.SetTypeAndClear(addressWotsHash)
		addr.SetKeyPairAddress(i)
		node = make([]byte, s.wotsPkLen())
		s.wotsPkGen(node, skSeed, pkSeed, addr)
	} else {
		lnode := s.xmssNodeRec(skSeed, 2*i, z-1, pkSeed, addr)
		rnode := s.xmssNodeRec(skSeed, 2*i+1, z-1, pkSeed, addr)
		addr.SetTypeAndClear(addressTree)
		addr.SetTreeHeight(z)
		addr.SetTreeIndex(i)
		node = make([]byte, s.wotsPkLen())
		s.hasher.H(node, pkSeed, addr.Bytes(), lnode, rnode)
	}

	return
}

func (s *state) xmssNodeIter(skSeed []byte, i, z uint32, pkSeed []byte, addr *address) (node []byte) {
	if !(z <= uint32(s.hPrime) && i < (1<<(uint32(s.hPrime)-z))) {
		panic(ErrNode)
	}

	var sh stackHash
	sh.new(int(1 << z))

	var si stackIndex
	si.push(index{i, z})

	buf := bytes.NewBuffer(make([]byte, (1<<z)*s.n))
	for !si.isEmpty() {
		it := si.pop()
		if it.z != 0 {
			si.push(index{2*it.i + 1, it.z - 1})
			si.push(index{2*it.i + 0, it.z - 1})
		} else {
			addr.SetTypeAndClear(addressWotsHash)
			addr.SetKeyPairAddress(it.i)
			node = buf.Next(s.n)
			s.wotsPkGen(node, skSeed, pkSeed, addr)

			li, lz := it.i, it.z
			for !sh.isEmpty() && sh.top().z == lz {
				left := sh.pop()
				li, lz = (li-1)/2, lz+1

				addr.SetTypeAndClear(addressTree)
				addr.SetTreeHeight(lz)
				addr.SetTreeIndex(li)
				s.hasher.H(node, pkSeed, addr.Bytes(), left.pk, node)
			}
			if sh.isEmpty() || sh.top().z != lz {
				sh.push(itemHash{lz, node})
			}
		}
	}

	if !sh.isEmpty() {
		node = sh.top().pk
	}

	return
}

type index struct{ i, z uint32 }
type stackIndex []index

func (s *stackIndex) isEmpty() bool { return len(*s) == 0 }
func (s *stackIndex) push(v index)  { *s = append(*s, v) }
func (s *stackIndex) pop() (v index) {
	last := len(*s) - 1
	if last >= 0 {
		v = (*s)[last]
		*s = (*s)[:last]
	}
	return
}

type itemHash struct {
	z  uint32
	pk wotsPublicKey
}
type stackHash []itemHash

func (s *stackHash) new(n int)       { *s = make([]itemHash, 0, n) }
func (s *stackHash) top() itemHash   { return (*s)[len(*s)-1] }
func (s *stackHash) isEmpty() bool   { return len(*s) == 0 }
func (s *stackHash) push(v itemHash) { *s = append(*s, v) }
func (s *stackHash) pop() (v itemHash) {
	last := len(*s) - 1
	if last >= 0 {
		v = (*s)[last]
		*s = (*s)[:last]
	}
	return
}

func (s *state) xmssSign(msg, skSeed []byte, idx uint32, pkSeed []byte, addr *address) (sig xmssSignature) {
	sig.authPath = make([][]byte, s.hPrime)
	for j := uint32(0); j < uint32(s.hPrime); j++ {
		k := (idx >> j) ^ 1
		sig.authPath[j] = s.xmssNode(skSeed, k, j, pkSeed, addr)
	}

	addr.SetTypeAndClear(addressWotsHash)
	addr.SetKeyPairAddress(idx)
	sig.wotsSig = make([]byte, s.wotsSigLen())
	s.wotsSign(sig.wotsSig, msg, skSeed, pkSeed, addr)

	return
}

func (p *params) xmssPkLen() int { return p.n }

func (s *state) xmssPkFromSig(pk xmssPublicKey, msg, pkSeed []byte, sig xmssSignature, idx uint32, addr *address) {
	addr.SetTypeAndClear(addressWotsHash)
	addr.SetKeyPairAddress(idx)
	s.wotsPkFromSig(wotsPublicKey(pk), sig.wotsSig, msg, pkSeed, addr)

	addr.SetTypeAndClear(addressTree)
	addr.SetTreeIndex(idx)
	for k := 0; k < s.hPrime; k++ {
		addr.SetTreeHeight(uint32(k + 1))
		if (idx>>k)&0x1 == 0 {
			addr.SetTreeIndex(addr.GetTreeIndex() >> 1)
			s.hasher.H(pk, pkSeed, addr.Bytes(), pk, sig.authPath[k])
		} else {
			addr.SetTreeIndex((addr.GetTreeIndex() - 1) >> 1)
			s.hasher.H(pk, pkSeed, addr.Bytes(), sig.authPath[k], pk)
		}
	}
}
