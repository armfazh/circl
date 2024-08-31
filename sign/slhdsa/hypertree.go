package slhdsa

import "bytes"

type hyperTreeSignature []xmssSignature // d*xmssSigSize() bytes

func (p *params) hyperTreeSigSize() int { return p.d * p.xmssSigSize() }

func (hts *hyperTreeSignature) fromBytes(p *params, c *cursor) {
	*hts = make([]xmssSignature, p.d)
	for i := 0; i < p.d; i++ {
		(*hts)[i].fromBytes(p, c)
	}
}

func nextIndex(idxTree *[3]uint32, n int) (idxLeaf uint32) {
	idxLeaf = idxTree[0] & ((1 << n) - 1)
	idxTree[0] = (idxTree[0] >> n) | (idxTree[1] << (32 - n))
	idxTree[1] = (idxTree[1] >> n) | (idxTree[2] << (32 - n))
	idxTree[2] = (idxTree[2] >> n)
	return
}

func (s *state) htSign(sig hyperTreeSignature, msg []byte, idxTree [3]uint32, idxLeaf uint32) {
	root := msg
	var a addressSolid
	addr := a.getPtr(s.params)
	addr.SetTreeAddress(idxTree)
	stack := s.newStack(s.hPrime)
	defer stack.clear()

	s.xmssSign(&stack, sig[0], root, idxLeaf, &addr)

	for j := uint32(1); j < uint32(s.d); j++ {
		root = s.xmssPkFromSig(root, sig[j-1], idxLeaf, &addr)
		idxLeaf = nextIndex(&idxTree, s.hPrime)
		addr.SetLayerAddress(j)
		addr.SetTreeAddress(idxTree)
		s.xmssSign(&stack, sig[j], root, idxLeaf, &addr)
	}
}

func (s *state) htVerify(msg, pkRoot []byte, idxTree [3]uint32, idxLeaf uint32, sig hyperTreeSignature) bool {
	var a addressSolid
	addr := a.getPtr(s.params)
	addr.SetTreeAddress(idxTree)
	node := s.xmssPkFromSig(msg, sig[0], idxLeaf, &addr)

	for j := uint32(1); j < uint32(s.d); j++ {
		idxLeaf = nextIndex(&idxTree, s.hPrime)
		addr.SetLayerAddress(j)
		addr.SetTreeAddress(idxTree)
		node = s.xmssPkFromSig(node, sig[j], idxLeaf, &addr)
	}

	return bytes.Equal(node, pkRoot)
}
