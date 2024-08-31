package slhdsa

type (
	forsPublicKey  []byte     // n bytes
	forsPrivateKey []byte     // n bytes
	forsSignature  []forsPair // k*forsPairSize() bytes
	forsPair       struct {   // forsSkSize() + a*n bytes
		sk   forsPrivateKey
		auth [][]byte
	}
)

func (p *params) forsPkSize() int   { return p.n }
func (p *params) forsSkSize() int   { return p.n }
func (p *params) forsSigSize() int  { return p.k * p.forsPairSize() }
func (p *params) forsPairSize() int { return p.forsSkSize() + p.a*p.n }

func (fs *forsSignature) fromBytes(p *params, c *cursor) {
	*fs = make([]forsPair, p.k)
	for i := 0; i < p.k; i++ {
		(*fs)[i].fromBytes(p, c)
	}
}

func (fp *forsPair) fromBytes(p *params, c *cursor) {
	fp.sk = c.Next(p.forsSkSize())
	fp.auth = make([][]byte, p.a)
	for i := 0; i < p.a; i++ {
		fp.auth[i] = c.Next(p.n)
	}
}

func (s *state) forsSkGen(sk forsPrivateKey, skSeed, pkSeed []byte, addr *address, idx uint32) {
	s.prf.SetAddress(addr)
	s.prf.address.SetTypeAndClear(addressForsPrf)
	s.prf.address.SetKeyPairAddress(addr.GetKeyPairAddress())
	s.prf.address.SetTreeIndex(idx)
	s.PRF_SumCopy(sk)
}

func (s *state) forsNodeIter(stack *stateStack, root, skSeed []byte, i, z uint32, pkSeed []byte, addr *address) {
	if !(z <= uint32(s.a) && i < uint32(s.k)*(1<<(uint32(s.a)-z))) {
		panic(ErrNode)
	}

	s.f.SetAddress(addr)
	s.f.address.SetTreeHeight(0)

	s.h.SetAddress(addr)

	twoZ := uint32(1) << z
	iTwoZ := i << z
	for k := uint32(0); k < twoZ; k++ {
		li := iTwoZ + k
		lz := uint32(0)

		sk := stack.si.pop().node
		s.forsSkGen(sk, skSeed, pkSeed, addr, li)
		s.f.address.SetTreeIndex(li)
		s.f.SetMsg(sk)

		node := sk
		s.F_SumCopy(node)

		for !stack.sh.isEmpty() && stack.sh.top().z == lz {
			left := stack.sh.pop()
			li = (li - 1) / 2
			lz = lz + 1

			s.h.address.SetTreeHeight(lz)
			s.h.address.SetTreeIndex(li)
			s.h.SetMsgs(left.node, node)
			s.H_SumCopy(node)
			stack.si.push(left)
		}
		stack.sh.push(item{lz, node})
	}

	last := stack.sh.pop()
	copy(root, last.node)
	stack.si.push(last)
}

func (s *state) forsNodeRec(node, skSeed []byte, i, z uint32, pkSeed []byte, addr *address) {
	if !(z <= uint32(s.a) && i < uint32(s.k)*(1<<(uint32(s.a)-z))) {
		panic(ErrNode)
	}

	if z == 0 {
		sk := make([]byte, s.forsSkSize())
		s.forsSkGen(sk, skSeed, pkSeed, addr, i)
		addr.SetTreeHeight(0)
		addr.SetTreeIndex(i)

		s.f.SetAddress(addr)
		s.f.SetMsg(sk)
		s.F_SumCopy(node)
	} else {
		lnode := make([]byte, s.n)
		s.forsNodeRec(lnode, skSeed, 2*i, z-1, pkSeed, addr)
		rnode := make([]byte, s.n)
		s.forsNodeRec(rnode, skSeed, 2*i+1, z-1, pkSeed, addr)

		s.h.SetAddress(addr)
		s.h.address.SetTreeHeight(z)
		s.h.address.SetTreeIndex(i)
		s.h.SetMsgs(lnode, rnode)
		s.H_SumCopy(node)
	}
}

func baseTwoB(x []byte, b, n int) (out []uint32) {
	out = make([]uint32, n)
	in := 0
	bits := 0
	total := uint32(0)
	maskB := (uint32(1) << b) - 1

	for i := 0; i < n; i++ {
		for bits < b {
			total = (total << 8) + uint32(x[in])
			in++
			bits += 8
		}
		bits -= b
		out[i] = (total >> bits) & maskB
	}

	return
}

func (s *state) forsSign(sig forsSignature, msgDigest []byte, skSeed, pkSeed []byte, addr *address) {
	indices := baseTwoB(msgDigest, s.a, s.k)

	stack := s.newStack(s.a)
	defer stack.clear()

	for i := uint32(0); i < uint32(s.k); i++ {
		s.forsSkGen(sig[i].sk, skSeed, pkSeed, addr, (i<<uint32(s.a))+indices[i])
		for j := uint32(0); j < uint32(s.a); j++ {
			sOffset := (indices[i] >> j) ^ 1
			s.forsNodeIter(&stack, sig[i].auth[j], skSeed, (i<<(uint32(s.a)-j))+sOffset, j, pkSeed, addr)
		}
	}
}

func (s *state) forsPkFromSig(msgDigest []byte, sig forsSignature, pkSeed []byte, addr *address) forsPublicKey {
	indices := baseTwoB(msgDigest, s.a, s.k)

	s.f.SetAddress(addr)
	s.f.address.SetTreeHeight(0)

	s.h.SetAddress(addr)

	s.t.SetAddress(addr)
	s.t.address.SetTypeAndClear(addressForsRoots)
	s.t.address.SetKeyPairAddress(addr.GetKeyPairAddress())
	s.T_Start()

	for i := uint32(0); i < uint32(s.k); i++ {
		treeIdx := (i << s.a) + indices[i]
		s.f.address.SetTreeIndex(treeIdx)
		s.f.SetMsg(sig[i].sk)
		node := s.F_SumByRef()

		s.h.address.SetTreeIndex(treeIdx)
		for j := uint32(0); j < uint32(s.a); j++ {
			s.h.address.SetTreeHeight(j + 1)
			if (indices[i]>>j)&0x1 == 0 {
				s.h.address.SetTreeIndex(s.h.address.GetTreeIndex() >> 1)
				s.h.SetMsgs(node, sig[i].auth[j])
			} else {
				s.h.address.SetTreeIndex((s.h.address.GetTreeIndex() - 1) >> 1)
				s.h.SetMsgs(sig[i].auth[j], node)
			}
			node = s.H_SumByRef()
		}
		s.T_AppendMsg(node)
	}

	return s.T_SumByRef()
}
