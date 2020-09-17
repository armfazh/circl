package group

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

func (g wePog) String() string                    { return g.Params().Name }
func (g wePog) Order() *big.Int                   { return g.Params().N }
func (g wePog) RandomElement(r io.Reader) Element { return g.MulGen(g.RandomScalar(r)) }
func (g wePog) Identity() Element                 { return weElt{big.NewInt(0), big.NewInt(0), g.bitSize} }
func (g wePog) Generator() Element                { return weElt{g.Params().Gx, g.Params().Gy, g.bitSize} }
func (g wePog) MulGen(n Scalar) Element {
	x, y := g.ScalarBaseMult(n.Bytes())
	return weElt{x, y, g.bitSize}
}
func (g wePog) IsIdentity(a Element) bool {
	aa := g.cvt(a)
	return aa.x.Sign() == 0 && aa.y.Sign() == 0
}
func (g wePog) IsValid(a Element) bool { aa := g.cvt(a); return g.IsOnCurve(aa.x, aa.y) }
func (g wePog) Marshal(a Element) []byte {
	aa := g.cvt(a)
	return elliptic.Marshal(g.Curve, aa.x, aa.y)
}
func (g wePog) AreEqual(a, b Element) bool {
	aa := g.cvt(a)
	bb := g.cvt(b)
	return aa.x.Cmp(bb.x) == 0 && aa.y.Cmp(bb.y) == 0
}
func (g wePog) Unmarshal(b []byte) (Element, error) {
	x, y := elliptic.Unmarshal(g.Curve, b)
	if x == nil && y == nil {
		return nil, ErrUnmarshal
	}
	return weElt{x, y, g.bitSize}, nil
}
func (g wePog) RandomScalar(r io.Reader) Scalar {
	if r == nil {
		r = rand.Reader
	}
	ord := g.Order()
	n, _ := rand.Int(r, ord)
	return &scalar{*n, *ord}
}
func (g wePog) Neg(a Element) Element {
	aa := g.cvt(a)
	return weElt{new(big.Int).Set(aa.x), new(big.Int).Neg(aa.y), g.bitSize}
}
func (g wePog) Add(a, b Element) Element {
	aa := g.cvt(a)
	bb := g.cvt(b)
	x, y := g.Curve.Add(aa.x, aa.y, bb.x, bb.y)
	return weElt{x, y, g.bitSize}
}
func (g wePog) Mul(a Element, n Scalar) Element {
	aa := g.cvt(a)
	x, y := g.ScalarMult(aa.x, aa.y, n.Bytes())
	return weElt{x, y, g.bitSize}
}
func (g wePog) cvt(a Element) weElt {
	aa, ok := a.(weElt)
	if ok && aa.bitSize == g.bitSize {
		return aa
	}
	panic(ErrBadElement)
}
