package secretsharing

import (
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/group"
)

type polynomial struct {
	deg   uint
	coeff []group.Scalar
}

func randomPolynomial(rnd io.Reader, g group.Group, deg uint) (p polynomial) {
	p = polynomial{deg, make([]group.Scalar, deg+1)}

	for i := 0; i <= int(deg); i++ {
		p.coeff[i] = g.RandomScalar(rnd)
	}
	return
}

func (p polynomial) String() (s string) {
	for i := int(p.deg); i >= 0; i-- {
		s += fmt.Sprintf("%v x^%v\n", p.coeff[i], i)
	}
	return
}

func (p polynomial) Evaluate(x group.Scalar) group.Scalar {
	px := p.coeff[p.deg].Copy()
	for i := int(p.deg) - 1; i >= 0; i-- {
		px.Mul(px, x)
		px.Add(px, p.coeff[i])
	}
	return px
}

func lagrangeCoefficient(g group.Group, p []point, index int) group.Scalar {
	if !(0 <= index && index < len(p)) {
		panic("invalid parameter")
	}

	num := g.NewScalar()
	num.SetUint64(1)
	den := g.NewScalar()
	den.SetUint64(1)
	tmp := g.NewScalar()

	for j := range p {
		if j != index {
			num.Mul(num, p[j].x)
			den.Mul(den, tmp.Sub(p[j].x, p[index].x))
		}
	}

	return num.Mul(num, tmp.Inv(den))
}

type point struct{ x, y group.Scalar }

func lagrangeInterpolate(g group.Group, p []point) (group.Scalar, error) {
	zero := g.NewScalar()
	for i := range p {
		if p[i].x.IsEqual(zero) {
			return nil, errors.New("lagrange: tried to evaluate on zero")
		}
	}

	pol0 := g.NewScalar()
	delta := g.NewScalar()
	for i := range p {
		pol0.Add(pol0, delta.Mul(p[i].y, lagrangeCoefficient(g, p, i)))
	}

	return pol0, nil
}
