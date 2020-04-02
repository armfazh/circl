package goldilocks

import (
	"crypto/subtle"

	"github.com/cloudflare/circl/internal/conv"
	"github.com/cloudflare/circl/math"
	fp "github.com/cloudflare/circl/math/fp448"
)

// twistCurve is -x^2+y^2=1-39082x^2y^2 and is 4-isogeneous to Goldilocks.
type twistCurve struct{}

// Identity returns the identity point.
func (twistCurve) Identity() *twistPoint {
	return &twistPoint{
		y: fp.One(),
		z: fp.One(),
	}
}

// ScalarMult returns kP.
func (twistCurve) ScalarMult(k []byte, P *twistPoint) *twistPoint { return &twistPoint{} }

// ScalarBaseMult returns kG where G is the generator point.
func (e twistCurve) ScalarBaseMult(scalar []byte) *twistPoint {
	if len(scalar) != ScalarSize {
		panic("wrong scalar size")
	}
	const ee = (fxT + fxW*fxV - 1) / (fxW * fxV)
	const dd = ee * fxV
	const ll = dd * fxW

	L := make([]int8, ll+1)
	mLSBRecoding(L[:], scalar)
	S := &pointR3{}
	P := e.Identity()
	for ii := ee - 1; ii >= 0; ii-- {
		P.Double()
		for j := 0; j < fxV; j++ {
			dig := L[fxW*dd-j*ee+ii-ee]
			for i := (fxW-1)*dd - j*ee + ii - ee; i >= (2*dd - j*ee + ii - ee); i = i - dd {
				dig = 2*dig + L[i]
			}
			idx := absolute(int32(dig))
			sig := L[dd-j*ee+ii-ee]
			Tabj := &tabSign[fxV-j-1]
			for k := 0; k < fx2w1; k++ {
				S.cmov(&Tabj[k], subtle.ConstantTimeEq(int32(k), idx))
			}
			S.cneg(subtle.ConstantTimeEq(int32(sig), -1))
			P.mixAdd(S)
		}
	}
	return P
}

const (
	omegaFix = 7
	omegaVar = 5
)

// CombinedMult returns mG+nP
func (e twistCurve) CombinedMult(m, n []byte, P *twistPoint) *twistPoint {
	nafFix := math.OmegaNAF(conv.BytesLe2BigInt(m), omegaFix)
	nafVar := math.OmegaNAF(conv.BytesLe2BigInt(n), omegaVar)

	if len(nafFix) > len(nafVar) {
		nafVar = append(nafVar, make([]int32, len(nafFix)-len(nafVar))...)
	} else if len(nafFix) < len(nafVar) {
		nafFix = append(nafFix, make([]int32, len(nafVar)-len(nafFix))...)
	}

	var TabQ [1 << (omegaVar - 2)]pointR2
	P.oddMultiples(TabQ[:])
	Q := e.Identity()
	for i := len(nafFix) - 1; i >= 0; i-- {
		Q.Double()
		// Generator point
		if nafFix[i] != 0 {
			idxM := absolute(nafFix[i]) >> 1
			R := tabVerif[idxM]
			if nafFix[i] < 0 {
				R.neg()
			}
			Q.mixAdd(&R)
		}
		// Variable input point
		if nafVar[i] != 0 {
			idxN := absolute(nafVar[i]) >> 1
			S := TabQ[idxN]
			if nafVar[i] < 0 {
				S.neg()
			}
			Q.add(&S)
		}
	}
	return Q
}
