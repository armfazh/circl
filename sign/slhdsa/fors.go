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

func (s *statePriv) forsSkGen(sk forsPrivateKey, addr address, idx uint32) {
	s.PRF.address.Set(addr)
	s.PRF.address.SetTypeAndClear(addressForsPrf)
	s.PRF.address.SetKeyPairAddress(addr.GetKeyPairAddress())
	s.PRF.address.SetTreeIndex(idx)
	s.PRF.SumCopy(sk)
}

func (s *statePriv) forsNodeIter(stack *stateStack, root []byte, i, z uint32, addr address) {
	if !(z <= uint32(s.a) && i < uint32(s.k)*(1<<(uint32(s.a)-z))) {
		panic(ErrNode)
	}

	s.F.address.Set(addr)
	s.F.address.SetTreeHeight(0)

	s.H.address.Set(addr)

	twoZ := uint32(1) << z
	iTwoZ := i << z
	for k := uint32(0); k < twoZ; k++ {
		li := iTwoZ + k
		lz := uint32(0)

		sk := stack.si.pop().node
		s.forsSkGen(sk, addr, li)
		s.F.address.SetTreeIndex(li)
		s.F.SetMsg(sk)

		node := sk
		s.F.SumCopy(node)

		for !stack.sh.isEmpty() && stack.sh.top().z == lz {
			left := stack.sh.pop()
			li = (li - 1) / 2
			lz = lz + 1

			s.H.address.SetTreeHeight(lz)
			s.H.address.SetTreeIndex(li)
			s.H.SetMsgs(left.node, node)
			s.H.SumCopy(node)
			stack.si.push(left)
		}
		stack.sh.push(item{lz, node})
	}

	last := stack.sh.pop()
	copy(root, last.node)
	stack.si.push(last)
}

func (s *statePriv) forsNodeRec(node []byte, i, z uint32, addr address) {
	if !(z <= uint32(s.a) && i < uint32(s.k)*(1<<(uint32(s.a)-z))) {
		panic(ErrNode)
	}

	if z == 0 {
		sk := make([]byte, s.forsSkSize())
		s.forsSkGen(sk, addr, i)
		addr.SetTreeHeight(0)
		addr.SetTreeIndex(i)

		s.F.address.Set(addr)
		s.F.SetMsg(sk)
		s.F.SumCopy(node)
	} else {
		lnode := make([]byte, s.n)
		s.forsNodeRec(lnode, 2*i, z-1, addr)
		rnode := make([]byte, s.n)
		s.forsNodeRec(rnode, 2*i+1, z-1, addr)

		s.H.address.Set(addr)
		s.H.address.SetTreeHeight(z)
		s.H.address.SetTreeIndex(i)
		s.H.SetMsgs(lnode, rnode)
		s.H.SumCopy(node)
	}
}

func (s *statePriv) forsSign(sig forsSignature, msgDigest []byte, addr address) {
	stack := s.NewStack(s.a)
	defer stack.Clear()

	in, bits, total := 0, 0, uint32(0)
	maskB := (uint32(1) << s.a) - 1

	for i := uint32(0); i < uint32(s.k); i++ {
		for bits < s.a {
			total = (total << 8) + uint32(msgDigest[in])
			in++
			bits += 8
		}
		bits -= s.a
		indicesI := (total >> bits) & maskB
		s.forsSkGen(sig[i].sk, addr, (i<<uint32(s.a))+indicesI)
		for j := uint32(0); j < uint32(s.a); j++ {
			sOffset := (indicesI >> j) ^ 1
			s.forsNodeIter(&stack, sig[i].auth[j], (i<<(uint32(s.a)-j))+sOffset, j, addr)
		}
	}
}

func (s *state) forsPkFromSig(msgDigest []byte, sig forsSignature, addr address) forsPublicKey {
	s.F.address.Set(addr)
	s.F.address.SetTreeHeight(0)

	s.H.address.Set(addr)

	s.T.address.Set(addr)
	s.T.address.SetTypeAndClear(addressForsRoots)
	s.T.address.SetKeyPairAddress(addr.GetKeyPairAddress())
	s.T.Start()

	in, bits, total := 0, 0, uint32(0)
	maskB := (uint32(1) << s.a) - 1

	for i := uint32(0); i < uint32(s.k); i++ {
		for bits < s.a {
			total = (total << 8) + uint32(msgDigest[in])
			in++
			bits += 8
		}
		bits -= s.a
		indicesI := (total >> bits) & maskB
		treeIdx := (i << s.a) + indicesI
		s.F.address.SetTreeIndex(treeIdx)
		s.F.SetMsg(sig[i].sk)
		node := s.F.SumByRef()

		s.H.address.SetTreeIndex(treeIdx)
		for j := uint32(0); j < uint32(s.a); j++ {
			s.H.address.SetTreeHeight(j + 1)
			if (indicesI>>j)&0x1 == 0 {
				s.H.address.SetTreeIndex(s.H.address.GetTreeIndex() >> 1)
				s.H.SetMsgs(node, sig[i].auth[j])
			} else {
				s.H.address.SetTreeIndex((s.H.address.GetTreeIndex() - 1) >> 1)
				s.H.SetMsgs(sig[i].auth[j], node)
			}
			node = s.H.SumByRef()
		}
		s.T.AppendMsg(node)
	}

	return s.T.SumByRef()
}
