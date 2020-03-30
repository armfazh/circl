package goldilocks

import (
	fp "github.com/cloudflare/circl/math/fp448"
)

// Curve is the Goldilocks curve x^2+y^2=z^2-39081x^2y^2.
type Curve struct{}

// Identity returns the identity point.
func (Curve) Identity() *Point {
	return &Point{
		y: fp.One(),
		z: fp.One(),
	}
}

// IsOnCurve returns true if the point lies on the curve.
func (Curve) IsOnCurve(P *Point) bool {
	x2, y2, z2 := &fp.Elt{}, &fp.Elt{}, &fp.Elt{}
	rhs, lhs := &fp.Elt{}, &fp.Elt{}
	fp.Sqr(x2, &P.x)          // x^2
	fp.Sqr(y2, &P.y)          // y^2
	fp.Sqr(z2, &P.z)          // y^2
	fp.Add(lhs, x2, y2)       // x^2 + y^2
	fp.Mul(rhs, x2, y2)       // x^2y^2
	fp.Mul(rhs, rhs, &paramD) // dx^2y^2
	fp.Add(rhs, rhs, z2)      // z^2 + dx^2y^2
	fp.Sub(lhs, lhs, rhs)     // x^2 + y^2 - (z^2 + dx^2y^2)
	eq0 := fp.IsZero(lhs)

	fp.Mul(lhs, &P.x, &P.y)   // xy
	fp.Mul(rhs, &P.ta, &P.tb) // t
	fp.Mul(rhs, rhs, &P.z)    // tz
	fp.Sub(lhs, lhs, rhs)     // xy - tz
	eq1 := fp.IsZero(lhs)
	return eq0 && eq1
}

// Generator returns the generator point.
func (Curve) Generator() *Point {
	return &Point{
		x:  genX,
		y:  genY,
		z:  fp.One(),
		ta: genX,
		tb: genY,
	}
}

// Double returns 2P.
func (Curve) Double(P *Point) *Point { return Curve{}.Add(P, P) }

// Add returns P+Q.
func (Curve) Add(P, Q *Point) *Point {
	R := &Point{}
	x1, y1, z1, ta1, tb1 := &P.x, &P.y, &P.z, &P.ta, &P.tb
	x2, y2, z2, ta2, tb2 := &Q.x, &Q.y, &Q.z, &Q.ta, &Q.tb
	x3, y3, z3, E, H := &R.x, &R.y, &R.z, &R.ta, &R.tb
	A, B, C, D, F, G := &R.x, &R.y, &R.z, &fp.Elt{}, &fp.Elt{}, &fp.Elt{}
	t1, t2 := &fp.Elt{}, &fp.Elt{}
	_D := &paramD
	fp.Mul(t1, ta1, tb1) // t1 = ta1*tb1
	fp.Mul(t2, ta2, tb2) // t2 = ta2*tb2
	fp.Mul(A, x1, x2)    // A = x1*x2
	fp.Mul(B, y1, y2)    // B = y1*y2
	fp.Mul(C, t1, t2)    // t1*t2
	fp.Mul(C, C, _D)     // C = d*t1*t2
	fp.Mul(D, z1, z2)    // D = z1*z2
	fp.Add(F, x1, y1)    // x1+y1
	fp.Add(E, x2, y2)    // x2+y2
	fp.Mul(E, E, F)      // (x1+y1)*(x2+y2)
	fp.Sub(E, E, A)      // (x1+y1)*(x2+y2)-A
	fp.Sub(E, E, B)      // E = (x1+y1)*(x2+y2)-A-B
	fp.Sub(F, D, C)      // F = D-C
	fp.Add(G, D, C)      // G = D+C
	fp.Add(H, B, A)      // H = B-A
	fp.Mul(x3, E, F)     // X = E * F
	fp.Mul(y3, G, H)     // Y = G * H
	fp.Mul(z3, F, G)     // Z = F * G, T = E * H
	return R
}

// ScalarBaseMult returns kG where G is the generator point.
func (e Curve) ScalarBaseMult(k []byte) *Point {
	var scalar [fp.Size]byte
	reduceModOrder(scalar[:])
	div4(scalar[:])
	P := twistCurve{}.ScalarBaseMult(scalar[:])
	return e.pull(P)
}

// ScalarMult returns kP.
func (e Curve) ScalarMult(k []byte, P *Point) *Point {
	div4(k[:])
	return e.pull(twistCurve{}.ScalarMult(k, e.push(P)))
}

// CombinedMult returns mG+nP.
func (e Curve) CombinedMult(m, n []byte, P *Point) *Point {
	div4(m[:])
	div4(n[:])
	return e.pull(twistCurve{}.CombinedMult(m, n, e.push(P)))
}
