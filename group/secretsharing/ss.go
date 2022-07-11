package secretsharing

import (
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/group"
)

type SecretShare struct {
	Id    uint
	share group.Scalar
}

type ShamirSS struct {
	G    group.Group
	T, N uint
	_    struct{}
}

func New(g group.Group, t, n uint) (*ShamirSS, error) {
	if !(0 < t && t <= n) || g == nil {
		return nil, errors.New("secretsharing: bad parameters")
	}
	return &ShamirSS{G: g, T: t, N: n}, nil
}

func (s ShamirSS) polyFromSecret(rnd io.Reader, secret group.Scalar) (p polynomial) {
	p = randomPolynomial(rnd, s.G, s.T)
	p.coeff[0] = secret.Copy()
	return
}

func (s ShamirSS) generateShares(poly polynomial) []SecretShare {
	shares := make([]SecretShare, s.N)
	x := s.G.NewScalar()
	for i := range shares {
		id := uint(i + 1)
		x.SetUint64(uint64(id))
		shares[i].Id = id
		shares[i].share = poly.evaluate(x)
	}

	return shares
}

func (s ShamirSS) ShardSecret(rnd io.Reader, secret group.Scalar) []SecretShare {
	return s.generateShares(s.polyFromSecret(rnd, secret))
}

func (s ShamirSS) RecoverSecret(shares []SecretShare) (group.Scalar, error) {
	if l := len(shares); l <= int(s.T) {
		return nil, fmt.Errorf("secretsharing: do not met threshold %v with %v shares", s.T, l)
	} else if l > int(s.N) {
		return nil, fmt.Errorf("secretsharing: %v shares above max number of shares %v", l, s.N)
	}

	x := make([]group.Scalar, len(shares))
	px := make([]group.Scalar, len(shares))
	for i := range shares {
		x[i] = s.G.NewScalar()
		x[i].SetUint64(uint64(shares[i].Id))
		px[i] = shares[i].share
	}

	return LagrangeInterpolate(s.G, x, px)
}

type Commitment []group.Element

type FeldmanSS struct {
	s ShamirSS
	_ struct{}
}

func NewVerifiable(g group.Group, t, n uint) (*FeldmanSS, error) {
	if !(0 < t && t <= n) || g == nil {
		return nil, errors.New("bad parameters")
	}
	return &FeldmanSS{s: ShamirSS{G: g, T: t, N: n}}, nil
}

func (f FeldmanSS) ShardSecret(rnd io.Reader, secret group.Scalar) ([]SecretShare, Commitment) {
	poly := f.s.polyFromSecret(rnd, secret)
	shares := f.s.generateShares(poly)

	vecComm := make(Commitment, f.s.T+1)
	for i, ki := range poly.coeff {
		vecComm[i] = f.s.G.NewElement()
		vecComm[i].MulGen(ki)
	}

	return shares, vecComm
}

func (f FeldmanSS) VerifyShare(s SecretShare, c Commitment) bool {
	if len(c) != int(f.s.T)+1 {
		return false
	}

	polI := f.s.G.NewElement().MulGen(s.share)

	lc := len(c) - 1
	sum := c[lc].Copy()
	x := f.s.G.NewScalar()
	for i := lc - 1; i >= 0; i-- {
		x.SetUint64(uint64(s.Id))
		sum.Mul(sum, x)
		sum.Add(sum, c[i])
	}

	return polI.IsEqual(sum)
}

func (f FeldmanSS) RecoverSecret(shares []SecretShare) (group.Scalar, error) {
	return f.s.RecoverSecret(shares)
}
