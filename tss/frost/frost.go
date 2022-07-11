package frost

import (
	"errors"
	"io"
	"sort"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/group/secretsharing"
)

type PublicKey group.Element

type Peer struct {
	Id       uint16
	keyShare group.Scalar
	g        group.Group
}

type SignShare struct {
	Id    uint16
	share group.Scalar
}

func (p Peer) Commit(rnd io.Reader) (Nonce, Commitment) {
	hidingNonce := nonceGenerate(rnd, p.keyShare)
	bindingNonce := nonceGenerate(rnd, p.keyShare)

	hidingNonceCom := p.g.NewElement().MulGen(hidingNonce)
	bindingNonceCom := p.g.NewElement().MulGen(bindingNonce)
	return Nonce{p.Id, hidingNonce, bindingNonce}, Commitment{p.Id, hidingNonceCom, bindingNonceCom}
}

func (p Peer) ShareSign(msg []byte, pubKey PublicKey, nonce Nonce, coms []Commitment) (*SignShare, error) {
	if p.Id != nonce.Id {
		return nil, errors.New("frost: bad id")
	}
	aux, err := common(p.g, uint(p.Id), msg, pubKey, coms)
	if err != nil {
		return nil, err
	}

	tmp := p.g.NewScalar().Mul(nonce.binding, aux.bindingFactor)
	signShare := p.g.NewScalar().Add(nonce.hiding, tmp)
	tmp.Mul(aux.lambdaId, p.keyShare)
	tmp.Mul(tmp, aux.challenge)
	signShare.Add(signShare, tmp)

	return &SignShare{Id: p.Id, share: signShare}, nil
}

func (s SignShare) Verify(
	g group.Group,
	pubKeySigner PublicKey,
	comSigner Commitment,
	coms []Commitment,
	pubKeyGroup PublicKey,
	msg []byte,
) bool {
	if s.Id != comSigner.Id || s.Id == 0 {
		return false
	}

	aux, err := common(g, uint(s.Id), msg, pubKeyGroup, coms)
	if err != nil {
		return false
	}

	comShare := g.NewElement().Mul(coms[aux.idx].binding, aux.bindingFactor)
	comShare.Add(comShare, coms[aux.idx].hiding)

	l := g.NewElement().MulGen(s.share)
	r := g.NewElement().Mul(pubKeySigner, g.NewScalar().Mul(aux.challenge, aux.lambdaId))
	r.Add(r, comShare)

	return l.IsEqual(r)
}

type commonAux struct {
	idx           uint
	lambdaId      group.Scalar
	challenge     group.Scalar
	bindingFactor group.Scalar
}

func common(g group.Group, id uint, msg []byte, pubKey PublicKey, coms []Commitment) (aux *commonAux, err error) {
	if !sort.SliceIsSorted(coms, func(i, j int) bool { return coms[i].Id < coms[j].Id }) {
		return nil, errors.New("frost:commitments must be sorted")
	}

	idx := sort.Search(len(coms), func(j int) bool { return uint(coms[j].Id) >= id })
	if !(idx < len(coms) && uint(coms[idx].Id) == id) {
		return nil, errors.New("frost: commitment not present")
	}

	comsEnc, err := encodeComs(coms)
	if err != nil {
		return nil, err
	}
	bindingFactor := getBindingFactor(comsEnc, msg)
	groupCom := getGroupCommitment(g, coms, bindingFactor)
	challenge, err := getChallenge(groupCom, pubKey, msg)
	if err != nil {
		return nil, err
	}

	x := make([]group.Scalar, len(coms))
	for i := range coms {
		x[i] = g.NewScalar()
		x[i].SetUint64(uint64(coms[i].Id))
	}
	lambdaId := secretsharing.LagrangeCoefficient(g, x, id)

	return &commonAux{
		idx:           uint(idx),
		lambdaId:      lambdaId,
		challenge:     challenge,
		bindingFactor: bindingFactor,
	}, nil
}

func Sign(g group.Group, groupCom Commitment, signShares []SignShare) ([]byte, error) {
	z := g.NewScalar()
	for i := range signShares {
		z.Add(z, signShares[i].share)
	}

	gcEnc, err := groupCom.MarshalBinary()
	if err != nil {
		return nil, err
	}
	zEnc, err := z.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return append(append([]byte{}, gcEnc...), zEnc...), nil
}

func Verify(g group.Group, msg, signature []byte, pubKey PublicKey) bool {
	params := g.Params()
	if len(signature) < int(params.ElementLength+params.ScalarLength) {
		return false
	}

	REnc := signature[:params.ElementLength]
	R := g.NewElement()
	err := R.UnmarshalBinary(REnc)
	if err != nil {
		return false
	}

	zEnc := signature[params.ElementLength : params.ElementLength+params.ScalarLength]
	z := g.NewScalar()
	err = z.UnmarshalBinary(zEnc)
	if err != nil {
		return false
	}

	pubKeyEnc, err := pubKey.MarshalBinary()
	if err != nil {
		return false
	}

	chInput := append(append([]byte{}, REnc...), pubKeyEnc...)
	c := h2(chInput)

	l := g.NewElement().MulGen(z)
	r := g.NewElement().Mul(pubKey, c)
	r.Add(r, R)

	return l.IsEqual(r)
}

func h1(m []byte) group.Scalar { return nil }
func h2(m []byte) group.Scalar { return nil }
func h3(m []byte) []byte       { return nil }
func h4(m []byte) group.Scalar { return nil }

func nonceGenerate(rnd io.Reader, s group.Scalar) group.Scalar {
	k := make([]byte, 32)
	_, _ = io.ReadFull(rnd, k)
	secretEnc, _ := s.MarshalBinary()
	return h4(append(append([]byte{}, k...), secretEnc...))
}
