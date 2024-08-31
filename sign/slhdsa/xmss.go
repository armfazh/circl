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

func (s *state) xmssNodeIter(stack *stateStack, root, skSeed []byte, i, z uint32, pkSeed []byte, addr *address) {
	if !(z <= uint32(s.hPrime) && i < (1<<(uint32(s.hPrime)-z))) {
		panic(ErrNode)
	}

	s.h.SetAddress(addr)
	s.h.address.SetTypeAndClear(addressTree)

	twoZ := uint32(1) << z
	iTwoZ := i << z
	for k := uint32(0); k < twoZ; k++ {
		li := iTwoZ + k
		lz := uint32(0)

		addr.SetTypeAndClear(addressWotsHash)
		addr.SetKeyPairAddress(li)
		node := stack.si.pop().node
		s.wotsPkGen(node, skSeed, pkSeed, addr)

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

func (s *state) xmssNodeRec(skSeed []byte, i, z uint32, pkSeed []byte, addr *address) (node []byte) {
	if !(z <= uint32(s.hPrime) && i < (1<<(uint32(s.hPrime)-z))) {
		panic(ErrNode)
	}

	if z == 0 {
		addr.SetTypeAndClear(addressWotsHash)
		addr.SetKeyPairAddress(i)
		node = make([]byte, s.wotsPkSize())
		s.wotsPkGen(node, skSeed, pkSeed, addr)
	} else {
		lnode := s.xmssNodeRec(skSeed, 2*i, z-1, pkSeed, addr)
		rnode := s.xmssNodeRec(skSeed, 2*i+1, z-1, pkSeed, addr)

		node = make([]byte, s.wotsPkSize())

		s.h.SetAddress(addr)
		s.h.address.SetTypeAndClear(addressTree)
		s.h.address.SetTreeHeight(z)
		s.h.address.SetTreeIndex(i)
		s.h.SetMsgs(lnode, rnode)
		s.H_SumCopy(node)
	}

	return
}

func (s *state) xmssSign(stack *stateStack, sig xmssSignature, msg, skSeed []byte, idx uint32, pkSeed []byte, addr *address) {
	curAuthPath := cursor(sig.authPath)
	for j := uint32(0); j < uint32(s.hPrime); j++ {
		k := (idx >> j) ^ 1
		s.xmssNodeIter(stack, curAuthPath.Next(s.n), skSeed, k, j, pkSeed, addr)
	}

	addr.SetTypeAndClear(addressWotsHash)
	addr.SetKeyPairAddress(idx)
	s.wotsSign(sig.wotsSig, msg, skSeed, pkSeed, addr)
}

func (s *state) xmssPkFromSig(msg, pkSeed []byte, sig xmssSignature, idx uint32, addr *address) (pk xmssPublicKey) {
	addr.SetTypeAndClear(addressWotsHash)
	addr.SetKeyPairAddress(idx)
	pk = xmssPublicKey(s.wotsPkFromSig(sig.wotsSig, msg, pkSeed, addr))

	s.h.SetAddress(addr)
	s.h.address.SetTypeAndClear(addressTree)
	s.h.address.SetTreeIndex(idx)

	curAuthPath := cursor(sig.authPath)
	for k := 0; k < s.hPrime; k++ {
		s.h.address.SetTreeHeight(uint32(k + 1))
		if (idx>>k)&0x1 == 0 {
			s.h.address.SetTreeIndex(s.h.address.GetTreeIndex() >> 1)
			s.h.SetMsgs(pk, curAuthPath.Next(s.n))
		} else {
			s.h.address.SetTreeIndex((s.h.address.GetTreeIndex() - 1) >> 1)
			s.h.SetMsgs(curAuthPath.Next(s.n), pk)
		}
		pk = s.H_SumByRef()
	}

	return
}
