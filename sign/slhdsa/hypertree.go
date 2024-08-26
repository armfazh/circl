package slhdsa

import (
	"bytes"

	"golang.org/x/crypto/cryptobyte"
)

type hyperTreeSignature []xmssSignature

func (hts *hyperTreeSignature) Marshal(b *cryptobyte.Builder) (err error) {
	for i := range *hts {
		b.AddValue(&(*hts)[i])
	}
	return
}

func (hts *hyperTreeSignature) Unmarshal(p *params, str *cryptobyte.String) bool {
	*hts = make([]xmssSignature, p.d)
	for i := 0; i < p.d; i++ {
		if !(*hts)[i].Unmarshal(p, str) {
			return false
		}
	}
	return true
}

func (s *state) htSign(sig hyperTreeSignature, msg, skSeed, pkSeed []byte, idxTree [3]uint32, idxLeaf uint32) {
	addr := s.newAddress()
	addr.SetTreeAddress(idxTree)

	sig[0].wotsSig = make([]byte, s.wotsSigLen())
	sig[0].authPath = make([]byte, s.xmssAuthPathLen())

	xs := s.newXmssState(uint32(s.hPrime))
	s.xmssSign(&xs, sig[0], msg, skSeed, idxLeaf, pkSeed, addr)

	root := s.xmssPkFromSig(msg, pkSeed, sig[0], idxLeaf, addr)
	hP := s.hPrime

	for j := uint32(1); j < uint32(s.d); j++ {
		idxLeafJ := idxTree[2] & ((1 << hP) - 1)
		idxTree[2] = (idxTree[1] << (32 - hP)) | (idxTree[2] >> hP)
		idxTree[1] = (idxTree[0] << (32 - hP)) | (idxTree[1] >> hP)
		idxTree[0] = /*************************/ (idxTree[0] >> hP)

		addr.SetLayerAddress(j)
		addr.SetTreeAddress(idxTree)

		sig[j].wotsSig = make([]byte, s.wotsSigLen())
		sig[j].authPath = make([]byte, s.xmssAuthPathLen())
		s.xmssSign(&xs, sig[j], root, skSeed, idxLeafJ, pkSeed, addr)
		if j < uint32(s.d)-1 {
			root = s.xmssPkFromSig(root, pkSeed, sig[j], idxLeafJ, addr)
		}
	}
}

func (s *state) htVerify(msg, pkSeed, pkRoot []byte, idxTree [3]uint32, idxLeaf uint32, sig hyperTreeSignature) bool {
	addr := s.newAddress()
	addr.SetTreeAddress(idxTree)
	node := s.xmssPkFromSig(msg, pkSeed, sig[0], idxLeaf, addr)
	hP := s.hPrime

	for j := uint32(1); j < uint32(s.d); j++ {
		idxLeaf := idxTree[2] & ((1 << hP) - 1)
		idxTree[2] = (idxTree[1] << (32 - hP)) | (idxTree[2] >> hP)
		idxTree[1] = (idxTree[0] << (32 - hP)) | (idxTree[1] >> hP)
		idxTree[0] = /*************************/ (idxTree[0] >> hP)

		addr.SetLayerAddress(j)
		addr.SetTreeAddress(idxTree)

		node = s.xmssPkFromSig(node, pkSeed, sig[j], idxLeaf, addr)
	}

	return bytes.Equal(node, pkRoot)
}
