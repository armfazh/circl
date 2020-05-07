package pog

import (
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"math/big"
)

type wePog struct {
	elliptic.Curve
	bitSize int
}

type weElt struct {
	x, y    *big.Int
	bitSize int
}

func (g wePog) String() string          { return g.Params().Name }
func (g wePog) Order() *big.Int         { return g.Params().N }
func (g wePog) RandomEE(r io.Reader) EE { return g.MulGen(g.RandomSC(r)) }
func (g wePog) Identity() EE            { return weElt{big.NewInt(0), big.NewInt(0), g.bitSize} }
func (g wePog) Generator() EE           { return weElt{g.Params().Gx, g.Params().Gy, g.bitSize} }
func (g wePog) MulGen(n SC) EE          { x, y := g.ScalarBaseMult(n.Bytes()); return weElt{x, y, g.bitSize} }
func (g wePog) IsIdentity(a EE) bool    { aa := g.cvt(a); return aa.x.Sign() == 0 && aa.y.Sign() == 0 }
func (g wePog) IsValid(a EE) bool       { aa := g.cvt(a); return g.IsOnCurve(aa.x, aa.y) }
func (g wePog) Marshal(a EE) []byte     { aa := g.cvt(a); return elliptic.Marshal(g.Curve, aa.x, aa.y) }
func (g wePog) AreEqual(a, b EE) bool {
	aa := g.cvt(a)
	bb := g.cvt(b)
	return aa.x.Cmp(bb.x) == 0 && aa.y.Cmp(bb.y) == 0
}
func (g wePog) Unmarshal(b []byte) (EE, error) {
	x, y := elliptic.Unmarshal(g.Curve, b)
	if x == nil && y == nil {
		return nil, ErrUnmarshal
	}
	return weElt{x, y, g.bitSize}, nil
}
func (g wePog) RandomSC(r io.Reader) SC {
	if r == nil {
		r = rand.Reader
	}
	ord := g.Order()
	n, _ := rand.Int(r, ord)
	return &scalar{*n, *ord}
}
func (g wePog) Neg(a EE) EE {
	aa := g.cvt(a)
	return weElt{new(big.Int).Set(aa.x), new(big.Int).Neg(aa.y), g.bitSize}
}
func (g wePog) Add(a, b EE) EE {
	aa := g.cvt(a)
	bb := g.cvt(b)
	x, y := g.Curve.Add(aa.x, aa.y, bb.x, bb.y)
	return weElt{x, y, g.bitSize}
}
func (g wePog) Mul(a EE, n SC) EE {
	aa := g.cvt(a)
	x, y := g.ScalarMult(aa.x, aa.y, n.Bytes())
	return weElt{x, y, g.bitSize}
}
func (g wePog) cvt(a EE) weElt {
	aa, ok := a.(weElt)
	if ok && aa.bitSize == g.bitSize {
		return aa
	}
	panic(ErrBadEE)
}
