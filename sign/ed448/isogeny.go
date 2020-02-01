package ed448

import (
	fp "github.com/cloudflare/circl/math/fp448"
)

type deg4isogeny struct{}

func (m deg4isogeny) Push(p *pointR1) {
	a := &fp.Elt{}
	fp.SetOne(a)
	m.deg4isogeny(p, a)
}
func (m deg4isogeny) Pull(p *pointR1) {
	a := &fp.Elt{}
	fp.SetOne(a)
	fp.Neg(a, a)
	m.deg4isogeny(p, a)
}
func (m deg4isogeny) deg4isogeny(P *pointR1, curveA *fp.Elt) {
	Px, Py, Pz, Pta, Ptb := &P.x, &P.y, &P.z, &P.ta, &P.tb
	a := &fp.Elt{}
	b := &fp.Elt{}
	c := &fp.Elt{}
	d := &fp.Elt{}
	e := &fp.Elt{}
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
	fp.Sub(g, b, d)      // G = B-D
	fp.Add(h, b, d)      // H = B+D
	fp.Sub(f, c, h)      // F = C-H
	fp.Mul(Px, e, f)     // X = E * F
	fp.Mul(Py, g, h)     // Y = G * H
	fp.Mul(Pz, f, g)     // Z = F * G
	*Pta, *Ptb = *e, *h  // T = E * H
}
