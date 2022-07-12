package frost

import (
	"errors"
	"io"
	"sort"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/group/secretsharing"
)

type PeerSigner struct {
	Suite
	Id       uint16
	keyShare group.Scalar
	myPubKey *PublicKey
}

func (p PeerSigner) Commit(rnd io.Reader) (*Nonce, *Commitment, error) {
	hidingNonce, err := p.Suite.nonceGenerate(rnd, p.keyShare)
	if err != nil {
		return nil, nil, err
	}
	bindingNonce, err := p.Suite.nonceGenerate(rnd, p.keyShare)
	if err != nil {
		return nil, nil, err
	}

	hidingNonceCom := p.Suite.g.NewElement().MulGen(hidingNonce)
	bindingNonceCom := p.Suite.g.NewElement().MulGen(bindingNonce)
	return &Nonce{p.Id, hidingNonce, bindingNonce}, &Commitment{p.Id, hidingNonceCom, bindingNonceCom}, nil
}

func (p PeerSigner) CheckKeyShare(keyShareCommits []KeyShareCommitment) bool {
	return secretsharing.SecretShare{Id: uint(p.Id), Share: p.keyShare}.Verify(p.Suite.g, keyShareCommits)
}

func (p PeerSigner) Public() *PublicKey {
	if p.myPubKey == nil {
		p.myPubKey = &PublicKey{p.Suite, p.Suite.g.NewElement().MulGen(p.keyShare)}
	}
	return p.myPubKey
}

func (p PeerSigner) Sign(msg []byte, pubKey *PublicKey, nonce *Nonce, coms []*Commitment) (*SignShare, error) {
	if p.Id != nonce.Id {
		return nil, errors.New("frost: bad id")
	}
	aux, err := p.Suite.common(uint(p.Id), msg, pubKey, coms)
	if err != nil {
		return nil, err
	}

	tmp := p.Suite.g.NewScalar().Mul(nonce.binding, aux.bindingFactor)
	signShare := p.Suite.g.NewScalar().Add(nonce.hiding, tmp)
	tmp.Mul(aux.lambdaId, p.keyShare)
	tmp.Mul(tmp, aux.challenge)
	signShare.Add(signShare, tmp)

	return &SignShare{Id: p.Id, share: signShare}, nil
}

type SignShare struct {
	Id    uint16
	share group.Scalar
}

func (s *SignShare) Verify(
	suite Suite,
	pubKeySigner *PublicKey,
	comSigner *Commitment,
	coms []*Commitment,
	pubKeyGroup *PublicKey,
	msg []byte,
) bool {
	if s.Id != comSigner.Id || s.Id == 0 {
		return false
	}

	aux, err := suite.common(uint(s.Id), msg, pubKeyGroup, coms)
	if err != nil {
		return false
	}

	comShare := suite.g.NewElement().Mul(coms[aux.idx].binding, aux.bindingFactor)
	comShare.Add(comShare, coms[aux.idx].hiding)

	l := suite.g.NewElement().MulGen(s.share)
	r := suite.g.NewElement().Mul(pubKeySigner.key, suite.g.NewScalar().Mul(aux.challenge, aux.lambdaId))
	r.Add(r, comShare)

	return l.IsEqual(r)
}

type commonAux struct {
	idx           uint
	lambdaId      group.Scalar
	challenge     group.Scalar
	bindingFactor group.Scalar
}

func (s Suite) common(id uint, msg []byte, pubKey *PublicKey, coms []*Commitment) (aux *commonAux, err error) {
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
	bindingFactor := s.getBindingFactor(comsEnc, msg)
	groupCom := s.getGroupCommitment(coms, bindingFactor)
	challenge, err := s.getChallenge(groupCom, pubKey, msg)
	if err != nil {
		return nil, err
	}

	x := make([]group.Scalar, len(coms))
	for i := range coms {
		x[i] = s.g.NewScalar()
		x[i].SetUint64(uint64(coms[i].Id))
	}
	lambdaId := secretsharing.LagrangeCoefficient(s.g, x, uint(idx))

	return &commonAux{
		idx:           uint(idx),
		lambdaId:      lambdaId,
		challenge:     challenge,
		bindingFactor: bindingFactor,
	}, nil
}
