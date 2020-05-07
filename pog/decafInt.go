package pog

import (
	"io"
	"math/big"
)

type decaf struct{}

func (d decaf) IsValid(a EE) bool              { return false }
func (d decaf) Add(a, b EE) EE                 { return nil }
func (d decaf) Neg(a EE) EE                    { return nil }
func (d decaf) Mul(a EE, n SC) EE              { return nil }
func (d decaf) MulGen(n SC) EE                 { return nil }
func (d decaf) Generator() EE                  { return nil }
func (d decaf) Identity() EE                   { return nil }
func (d decaf) Order() *big.Int                { return nil }
func (d decaf) Marshal(a EE) []byte            { return nil }
func (d decaf) Unmarshal(b []byte) (EE, error) { return nil, nil }
func (d decaf) RandomEE(io.Reader) EE          { return nil }
func (d decaf) RandomSC(io.Reader) SC          { return nil }

// RandomElt is
// func (d Decaf) RandomElt(r io.Reader) *Elt { return g.MulGen(g.RandomScalar(r)) }

// RandomScalar is
// func (d Decaf) RandomScalar(r io.Reader) goldilocks.Scalar {
// 	if r == nil {
// 		r = rand.Reader
// 	}
// 	var n goldilocks.Scalar
// 	_, _ = io.ReadFull(r, n[:])
// 	n.Red()
// 	return n
// }
