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
	*hts = make(hyperTreeSignature, p.d)
	for i := uint(0); i < p.d; i++ {
		if !(*hts)[i].Unmarshal(p, str) {
			return false
		}
	}
	return true
}

func (s *state) htSign(msg, skSeed, pkSeed []byte, idxTree [3]uint32, idxLeaf uint32) (sig hyperTreeSignature) {
	sig = make([]xmssSignature, s.d)

	var addr address
	addr.SetTreeAddress(idxTree)
	sig[0] = s.xmssSign(msg, skSeed, idxLeaf, pkSeed, addr)
	root := s.xmssPkFromSig(msg, pkSeed, sig[0], idxLeaf, addr)
	hPrime := s.hPrime

	for j := uint32(1); j < uint32(s.d); j++ {
		idxLeaf := idxTree[2] & ((1 << hPrime) - 1)
		idxTree[2] = (idxTree[1] << (32 - hPrime)) | (idxTree[2] >> hPrime)
		idxTree[1] = (idxTree[0] << (32 - hPrime)) | (idxTree[1] >> hPrime)
		idxTree[0] = /*****************************/ (idxTree[0] >> hPrime)

		addr.SetLayerAddress(j)
		addr.SetTreeAddress(idxTree)

		sig[j] = s.xmssSign(root, skSeed, idxLeaf, pkSeed, addr)
		if j < uint32(s.d)-1 {
			root = s.xmssPkFromSig(root, pkSeed, sig[j], idxLeaf, addr)
		}
	}

	return
}

func (s *state) htVerify(msg, pkSeed, pkRoot []byte, idxTree [3]uint32, idxLeaf uint32, sig hyperTreeSignature) bool {
	var addr address
	addr.SetTreeAddress(idxTree)
	node := s.xmssPkFromSig(msg, pkSeed, sig[0], idxLeaf, addr)
	hPrime := s.hPrime

	for j := uint32(1); j < uint32(s.d); j++ {
		idxLeaf := idxTree[2] & ((1 << hPrime) - 1)
		idxTree[2] = (idxTree[1] << (32 - hPrime)) | (idxTree[2] >> hPrime)
		idxTree[1] = (idxTree[0] << (32 - hPrime)) | (idxTree[1] >> hPrime)
		idxTree[0] = /*****************************/ (idxTree[0] >> hPrime)

		addr.SetLayerAddress(j)
		addr.SetTreeAddress(idxTree)

		node = s.xmssPkFromSig(node, pkSeed, sig[j], idxLeaf, addr)
	}

	return bytes.Equal(node, pkRoot)
}
