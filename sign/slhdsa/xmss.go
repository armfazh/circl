package slhdsa

// See FIPS 205 -- Section 6
// eXtended Merkle Signature Scheme (XMSS) extends the WOTS+ signature
// scheme into one that can sign multiple messages.

type (
	xmssPublicKey []byte // n bytes
	xmssSignature struct {
		wotsSig  wotsSignature // wotsSigSize() bytes
		authPath []byte        // hPrime*n bytes
	} // wotsSigSize() + hPrime*n bytes
)

func (p *params) xmssAuthPathSize() int { return p.hPrime * p.n }
func (p *params) xmssSigSize() int {
	return p.wotsSigSize() + p.xmssAuthPathSize()
}

func (xs *xmssSignature) fromBytes(p *params, c *cursor) {
	xs.wotsSig.fromBytes(p, c)
	xs.authPath = c.Next(p.xmssAuthPathSize())
}

// See FIPS 205 -- Section 6.1.
func (s *statePriv) xmssNodeIter(
	stack *stateStack, root []byte, i, z uint32, addr address,
) {
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

// See FIPS 205 -- Section 6.1 -- Algorithm 9.
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

// See FIPS 205 -- Section 6.2 -- Algorithm 10.
func (s *statePriv) xmssSign(
	stack *stateStack, sig xmssSignature, msg []byte, idx uint32, addr address,
) {
	authPath := cursor(sig.authPath)
	for j := uint32(0); j < uint32(s.hPrime); j++ {
		k := (idx >> j) ^ 1
		s.xmssNodeIter(stack, authPath.Next(s.n), k, j, addr)
	}

	addr.SetTypeAndClear(addressWotsHash)
	addr.SetKeyPairAddress(idx)
	s.wotsSign(sig.wotsSig, msg, addr)
}

// See FIPS 205 -- Section 6.3 -- Algorithm 11.
func (s *state) xmssPkFromSig(
	msg []byte, sig xmssSignature, idx uint32, addr address,
) (pk xmssPublicKey) {
	addr.SetTypeAndClear(addressWotsHash)
	addr.SetKeyPairAddress(idx)
	pk = xmssPublicKey(s.wotsPkFromSig(sig.wotsSig, msg, addr))

	treeIdx := idx
	s.H.address.Set(addr)
	s.H.address.SetTypeAndClear(addressTree)

	authPath := cursor(sig.authPath)
	for k := 0; k < s.hPrime; k++ {
		if (idx>>k)&0x1 == 0 {
			treeIdx = treeIdx >> 1
			s.H.SetMsgs(pk, authPath.Next(s.n))
		} else {
			treeIdx = (treeIdx - 1) >> 1
			s.H.SetMsgs(authPath.Next(s.n), pk)
		}

		s.H.address.SetTreeHeight(uint32(k + 1))
		s.H.address.SetTreeIndex(treeIdx)
		pk = s.H.SumByRef()
	}

	return
}
