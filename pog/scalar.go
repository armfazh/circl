package pog

import "math/big"

type scalar struct{ n, p big.Int }

func (z scalar) String() string { return "0x" + z.n.Text(16) }
func (z *scalar) Add(x, y SC)   { xx := z.cvt(x); yy := z.cvt(y); z.n.Add(&xx.n, &yy.n).Mod(&z.n, &z.p) }
func (z *scalar) Sub(x, y SC)   { xx := z.cvt(x); yy := z.cvt(y); z.n.Sub(&xx.n, &yy.n).Mod(&z.n, &z.p) }
func (z *scalar) Mul(x, y SC)   { xx := z.cvt(x); yy := z.cvt(y); z.n.Mul(&xx.n, &yy.n).Mod(&z.n, &z.p) }
func (z *scalar) Neg(x SC)      { xx := z.cvt(x); z.n.Neg(&xx.n).Mod(&z.n, &z.p) }
func (z *scalar) Inv(x SC)      { xx := z.cvt(x); z.n.ModInverse(&xx.n, &z.p) }
func (z *scalar) Bytes() []byte { return z.n.Bytes() }
func (z *scalar) cvt(x SC) *scalar {
	xx, ok := x.(*scalar)
	if ok && z.p.Cmp(&xx.p) == 0 {
		return xx
	}
	panic(ErrScalar)
}
