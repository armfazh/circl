package ed448

import (
	fp "github.com/cloudflare/circl/math/fp448"
)

type deg4isogeny struct{}

func (m *deg4isogeny) Push(p *pointR1) {
	a, d := &fp.Elt{}, &fp.Elt{}
	fp.SetOne(a)
	*d = paramD
	m.deg4isogeny(p, a, d)
}
func (m *deg4isogeny) Pull(p *pointR1) {
	a, d := &fp.Elt{}, &fp.Elt{}
	fp.SetOne(a)
	fp.Neg(a, a)
	*d = paramD
	d[0]--
	m.deg4isogeny(p, a, d)
}
func (m *deg4isogeny) deg4isogeny(P *pointR1, curveA, curveD *fp.Elt) {
	Px, Py, Pz, Pta, Ptb := &P.x, &P.y, &P.z, &P.ta, &P.tb
	a := Px
	b := Py
	c := Pz
	d := Pta
	e := Ptb
	f, g, h := &fp.Elt{}, &fp.Elt{}, &fp.Elt{}
	fp.Add(e, Px, Py)    // x+y
	fp.Sqr(a, Px)        // A = x^2
	fp.Sqr(b, Py)        // B = y^2
	fp.Sqr(c, Pz)        // z^2
	fp.Add(c, c, c)      // C = 2*z^2
	fp.Mul(d, curveA, a) // D = a*A
	fp.Sqr(e, e)         // (x+y)^2
	fp.Sub(e, e, a)      // (x+y)^2-A
	fp.Sub(e, e, b)      // E = (x+y)^2-A-B
	fp.Add(g, d, b)      // G = D+B
	fp.Sub(f, g, c)      // F = G-C
	fp.Sub(h, d, b)      // H = D-B
	fp.Mul(Px, e, f)     // X = E * F
	fp.Mul(Py, g, h)     // Y = G * H
	fp.Mul(Pz, f, h)     // Z = F * H
	*Pta, *Ptb = *e, *g  // T = E * G
}
