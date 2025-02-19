// Code generated from ./templates/poly.go.tmpl. DO NOT EDIT.

package fp128

import "github.com/cloudflare/circl/math"

type Poly []Fp

func (p Poly) AddAssign(x Poly) { Vec(p).AddAssign(Vec(x)) }
func (p Poly) SubAssign(x Poly) { Vec(p).SubAssign(Vec(x)) }
func (p Poly) Mul(x, y Poly) {
	mustSumLen(p, x, y)
	clear(p)
	var xiyj Fp
	for i := range x {
		for j := range y {
			xiyj.Mul(&x[i], &y[j])
			p[i+j].AddAssign(&xiyj)
		}
	}
}

func (p Poly) Sqr(x Poly) {
	mustSumLen(p, x, x)
	clear(p)
	for i := range x {
		p[2*i].Sqr(&x[i])
	}

	var xixj Fp
	for i := 0; i < len(x); i++ {
		for j := i + 1; j < len(x); j++ {
			xixj.Mul(&x[i], &x[j])
			xixj.AddAssign(&xixj)
			p[i+j].AddAssign(&xixj)
		}
	}
}

func (p Poly) Evaluate(x *Fp) (px Fp) {
	if l := len(p); l != 0 {
		px = p[l-1]
		for i := l - 2; i >= 0; i-- {
			px.MulAssign(x)
			px.AddAssign(&p[i])
		}
	}

	return
}

func (p Poly) Strip() Poly {
	for i := len(p) - 1; i >= 0; i-- {
		if !p[i].IsZero() {
			return p[:i+1]
		}
	}

	return p[:0]
}

func (p Poly) Interpolate(values []Fp) {
	_, logN := math.NextPow2(uint(len(values)))
	Vec(p).InvNTT(values)
	var invN Fp
	invN.InvTwoN(logN)
	Vec(p).ScalarMul(&invN)
}
