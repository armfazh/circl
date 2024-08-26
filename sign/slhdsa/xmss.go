package slhdsa

import (
	"bytes"

	"golang.org/x/crypto/cryptobyte"
)

type (
	xmssPublicKey []byte // n bytes
	xmssSignature struct {
		wotsSig  wotsSignature // wotsLen*n bytes
		authPath []byte        // hPrime*n bytes
	}
)

func (p *params) xmssSigLen() int      { return p.wotsSigLen() + p.xmssAuthPathLen() }
func (p *params) xmssAuthPathLen() int { return p.hPrime * p.n }

func (xs *xmssSignature) Marshal(b *cryptobyte.Builder) (err error) {
	b.AddValue(&xs.wotsSig)
	b.AddBytes(xs.authPath)
	return
}

func (xs *xmssSignature) Unmarshal(p *params, str *cryptobyte.String) bool {
	xs.authPath = make([]byte, p.hPrime*p.n)
	return xs.wotsSig.Unmarshal(p, str) && str.CopyBytes(xs.authPath)
}

type xmssState struct {
	sh    stackHash
	si    stackIndex
	nodes []byte
}

func (p *params) newXmssState(z uint32) (s xmssState) {
	s.sh.new(int(z))
	s.si.new(int(z + 1))
	s.nodes = make([]byte, (1<<z)*p.n)
	return
}

func (s *state) xmssNode(xs *xmssState, node, skSeed []byte, i, z uint32, pkSeed []byte, addr *address) {
	s.xmssNodeIter(xs, node, skSeed, i, z, pkSeed, addr)
}

type (
	itemIndex  struct{ i, z uint32 }
	stackIndex []itemIndex
)

func (s *stackIndex) new(n int)        { *s = make([]itemIndex, 0, n) }
func (s *stackIndex) isEmpty() bool    { return len(*s) == 0 }
func (s *stackIndex) push(v itemIndex) { *s = append(*s, v) }
func (s *stackIndex) pop() (v itemIndex) {
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

func (s *state) xmssNodeIter(xs *xmssState, root, skSeed []byte, i, z uint32, pkSeed []byte, addr *address) {
	if !(z <= uint32(s.hPrime) && i < (1<<(uint32(s.hPrime)-z))) {
		panic(ErrNode)
	}

	xs.si.push(itemIndex{i, z})
	buf := bytes.NewBuffer(xs.nodes)
	for !xs.si.isEmpty() {
		it := xs.si.pop()
		if it.z != 0 {
			xs.si.push(itemIndex{2*it.i + 1, it.z - 1})
			xs.si.push(itemIndex{2*it.i + 0, it.z - 1})
		} else {
			addr.SetTypeAndClear(addressWotsHash)
			addr.SetKeyPairAddress(it.i)
			node := buf.Next(s.n)
			s.wotsPkGen(node, skSeed, pkSeed, addr)

			li, lz := it.i, it.z
			for !xs.sh.isEmpty() && xs.sh.top().z == lz {
				left := xs.sh.pop()
				li, lz = (li-1)/2, lz+1

				addr.SetTypeAndClear(addressTree)
				addr.SetTreeHeight(lz)
				addr.SetTreeIndex(li)
				s.hasher.H(node, pkSeed, addr.Bytes(), left.pk, node)
			}
			xs.sh.push(itemHash{lz, node})
		}
	}

	copy(root, xs.sh.pop().pk)
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

func (s *state) xmssSign(xs *xmssState, sig xmssSignature, msg, skSeed []byte, idx uint32, pkSeed []byte, addr *address) {
	authPath := bytes.NewBuffer(sig.authPath)
	for j := uint32(0); j < uint32(s.hPrime); j++ {
		k := (idx >> j) ^ 1
		s.xmssNode(xs, authPath.Next(s.n), skSeed, k, j, pkSeed, addr)
	}

	addr.SetTypeAndClear(addressWotsHash)
	addr.SetKeyPairAddress(idx)
	s.wotsSign(sig.wotsSig, msg, skSeed, pkSeed, addr)
}

func (s *state) xmssPkFromSig(msg, pkSeed []byte, sig xmssSignature, idx uint32, addr *address) (pk xmssPublicKey) {
	addr.SetTypeAndClear(addressWotsHash)
	addr.SetKeyPairAddress(idx)
	pk = xmssPublicKey(s.wotsPkFromSig(sig.wotsSig, msg, pkSeed, addr))

	addr.SetTypeAndClear(addressTree)
	addr.SetTreeIndex(idx)
	authPath := bytes.NewBuffer(sig.authPath)
	for k := 0; k < s.hPrime; k++ {
		addr.SetTreeHeight(uint32(k + 1))
		if (idx>>k)&0x1 == 0 {
			addr.SetTreeIndex(addr.GetTreeIndex() >> 1)
			s.hasher.H(pk, pkSeed, addr.Bytes(), pk, authPath.Next(s.n))
		} else {
			addr.SetTreeIndex((addr.GetTreeIndex() - 1) >> 1)
			s.hasher.H(pk, pkSeed, addr.Bytes(), authPath.Next(s.n), pk)
		}
	}
	return
}
