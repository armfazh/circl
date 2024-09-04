package slhdsa

type (
	xmssPublicKey []byte   // n bytes
	xmssSignature struct { // wotsSigSize() + hPrime*n bytes
		wotsSig  wotsSignature
		authPath []byte
	}
)

func (p *params) xmssSigSize() int      { return p.wotsSigSize() + p.xmssAuthPathSize() }
func (p *params) xmssAuthPathSize() int { return p.hPrime * p.n }

func (xs *xmssSignature) fromBytes(p *params, c *cursor) {
	xs.wotsSig.fromBytes(p, c)
	xs.authPath = c.Next(p.xmssAuthPathSize())
}

func (s *statePriv) xmssNodeIter(stack *stateStack, root []byte, i, z uint32, addr address) {
	if !(z <= uint32(s.hPrime) && i < (1<<(uint32(s.hPrime)-z))) {
		panic(ErrTree)
	}

	s.H.address.Set(addr)
	s.H.address.SetTypeAndClear(addressTree)

	twoZ := uint32(1) << z
	iTwoZ := i << z
	for k := uint32(0); k < twoZ; k++ {
		li := iTwoZ + k
		lz := uint32(0)

		addr.SetTypeAndClear(addressWotsHash)
		addr.SetKeyPairAddress(li)
		node := stack.si.pop().node
		s.wotsPkGen(node, addr)

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

func (s *statePriv) xmssNodeRec(i, z uint32, addr address) (node []byte) {
	if !(z <= uint32(s.hPrime) && i < (1<<(uint32(s.hPrime)-z))) {
		panic(ErrTree)
	}

	if z == 0 {
		addr.SetTypeAndClear(addressWotsHash)
		addr.SetKeyPairAddress(i)
		node = make([]byte, s.wotsPkSize())
		s.wotsPkGen(node, addr)
	} else {
		lnode := s.xmssNodeRec(2*i, z-1, addr)
		rnode := s.xmssNodeRec(2*i+1, z-1, addr)

		node = make([]byte, s.wotsPkSize())

		s.H.address.Set(addr)
		s.H.address.SetTypeAndClear(addressTree)
		s.H.address.SetTreeHeight(z)
		s.H.address.SetTreeIndex(i)
		s.H.SetMsgs(lnode, rnode)
		s.H.SumCopy(node)
	}

	return
}

func (s *statePriv) xmssSign(stack *stateStack, sig xmssSignature, msg []byte, idx uint32, addr address) {
	curAuthPath := cursor(sig.authPath)
	for j := uint32(0); j < uint32(s.hPrime); j++ {
		k := (idx >> j) ^ 1
		s.xmssNodeIter(stack, curAuthPath.Next(s.n), k, j, addr)
	}

	addr.SetTypeAndClear(addressWotsHash)
	addr.SetKeyPairAddress(idx)
	s.wotsSign(sig.wotsSig, msg, addr)
}

func (s *state) xmssPkFromSig(msg []byte, sig xmssSignature, idx uint32, addr address) (pk xmssPublicKey) {
	addr.SetTypeAndClear(addressWotsHash)
	addr.SetKeyPairAddress(idx)
	pk = xmssPublicKey(s.wotsPkFromSig(sig.wotsSig, msg, addr))

	s.H.address.Set(addr)
	s.H.address.SetTypeAndClear(addressTree)
	s.H.address.SetTreeIndex(idx)

	curAuthPath := cursor(sig.authPath)
	for k := 0; k < s.hPrime; k++ {
		s.H.address.SetTreeHeight(uint32(k + 1))
		if (idx>>k)&0x1 == 0 {
			s.H.address.SetTreeIndex(s.H.address.GetTreeIndex() >> 1)
			s.H.SetMsgs(pk, curAuthPath.Next(s.n))
		} else {
			s.H.address.SetTreeIndex((s.H.address.GetTreeIndex() - 1) >> 1)
			s.H.SetMsgs(curAuthPath.Next(s.n), pk)
		}
		pk = s.H.SumByRef()
	}

	return
}
