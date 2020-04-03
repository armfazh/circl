package goldilocks

import (
	"crypto/subtle"

	fp "github.com/cloudflare/circl/math/fp448"
)

// ScalarBaseMult returns kG where G is the generator point.
func (e twistCurve) ScalarBaseMult(k []byte) *twistPoint { return fixMult.Exp(e, k).(*twistPoint) }

type preTwistPoint struct{ addYX, subYX, dt2 fp.Elt }

func (P *preTwistPoint) neg() {
	P.addYX, P.subYX = P.subYX, P.addYX
	fp.Neg(&P.dt2, &P.dt2)
}

func (P *preTwistPoint) cneg(b int) {
	t := &fp.Elt{}
	fp.Cswap(&P.addYX, &P.subYX, uint(b))
	fp.Neg(t, &P.dt2)
	fp.Cmov(&P.dt2, t, uint(b))
}

func (P *preTwistPoint) cmov(Q *preTwistPoint, b int) {
	fp.Cmov(&P.addYX, &Q.addYX, uint(b))
	fp.Cmov(&P.subYX, &Q.subYX, uint(b))
	fp.Cmov(&P.dt2, &Q.dt2, uint(b))
}

func (e twistCurve) Sqr(x GElt)         { x.(*twistPoint).Double() }
func (e twistCurve) Mul(x GElt, y TElt) { x.(*twistPoint).mixAdd(y.(*preTwistPoint)) }
func (e twistCurve) One() GElt          { return e.Identity() }
func (e twistCurve) TableElt() TElt     { return &preTwistPoint{} }
func (e twistCurve) Lookup(a TElt, idTable int, sgnElt int, idElt int) {
	Tabj := &tabFixMult[idTable]
	S := a.(*preTwistPoint)
	for k := range Tabj {
		S.cmov(&Tabj[k], subtle.ConstantTimeEq(int32(k), int32(idElt)))
	}
	S.cneg(sgnElt)
}
