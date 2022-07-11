package frost

import (
	"io"
	"sort"

	"github.com/cloudflare/circl/group"
)

type PublicKey group.Element

type Peer struct {
	Id       uint16
	keyShare group.Scalar
	g        group.Group
}

func (p Peer) Commit(rnd io.Reader) (Nonce, Commitment) {
	hidingNonce := nonceGenerate(rnd, p.keyShare)
	bindingNonce := nonceGenerate(rnd, p.keyShare)

	hidingNonceCom := p.g.NewElement().MulGen(hidingNonce)
	bindingNonceCom := p.g.NewElement().MulGen(bindingNonce)
	return Nonce{p.Id, hidingNonce, bindingNonce}, Commitment{p.Id, hidingNonceCom, bindingNonceCom}
}

func (p Peer) ShareSign(msg []byte, pubKey PublicKey, nonce Nonce, coms []Commitment) ([]byte, error) {
	if p.Id != nonce.Id {
		panic("frost: bad id")
	}

	if !sort.SliceIsSorted(coms, func(i, j int) bool { return coms[i].Id < coms[j].Id }) {
		panic("Commitments must be sorted")
	}

	comsEnc, err := encodeComs(coms)
	if err != nil {
		return nil, err
	}
	bindingFactor := calcBindingFactor(comsEnc, msg)
	groupCom := calcGroupCommitment(p.g, coms, bindingFactor)

	return nil, nil

}

func h1(m []byte) group.Scalar { return nil }
func h3(m []byte) []byte       { return nil }
func h2(m []byte) group.Scalar { return nil }
func h4(m []byte) group.Scalar { return nil }

func nonceGenerate(rnd io.Reader, s group.Scalar) group.Scalar {
	k := make([]byte, 32)
	_, _ = io.ReadFull(rnd, k)
	secretEnc, _ := s.MarshalBinary()
	return h4(append(append([]byte{}, k...), secretEnc...))
}
