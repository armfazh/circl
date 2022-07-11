package frost

import (
	"fmt"
	"io"

	"github.com/cloudflare/circl/group"
)

func h1(m []byte) group.Scalar { return nil }
func h3(m []byte) []byte       { return nil }
func h2(m []byte) group.Scalar { return nil }
func h4(m []byte) group.Scalar { return nil }

func nonceGenerator(rnd io.Reader, s group.Scalar) group.Scalar {
	k := make([]byte, 32)
	_, _ = io.ReadFull(rnd, k)
	secretEnc, _ := s.MarshalBinary()
	return h4(append(append([]byte{}, k...), secretEnc...))
}

type polynomial struct {
	g     group.Group
	deg   uint
	coeff []group.Scalar
}

func (p polynomial) String() (s string) {
	for i := int(p.deg); i >= 0; i-- {
		s += fmt.Sprintf("%v x^%v\n", p.coeff[i], i)
	}
	return
}

func (p polynomial) Evaluate(x group.Scalar) group.Scalar {
	px := p.coeff[p.deg]
	for i := int(p.deg) - 1; i >= 0; i-- {
		px.Mul(px, x)
		px.Add(px, p.coeff[i])
	}
	return px
}

type lagrange struct{ g group.Group }

func (l lagrange) basisCoeff(p []point, index int) group.Scalar {
	zero := l.g.NewScalar()

	if !(0 <= index && index < len(p)) {
		panic("invalid parameter")
	}

	for _, pj := range p {
		if pj.x.IsEqual(zero) {
			panic("invalid parameter")
		}
	}

	num := l.g.NewScalar()
	num.SetUint64(1)
	den := l.g.NewScalar()
	den.SetUint64(1)
	tmp := l.g.NewScalar()

	for j, pj := range p {
		if j != index {
			num.Mul(num, pj.x)
			den.Mul(den, tmp.Sub(pj.x, p[index].x))
		}
	}

	return num.Mul(num, tmp.Inv(den))
}

type point struct{ x, y group.Scalar }

func (l lagrange) Interpolate(p []point) group.Scalar {
	pol0 := l.g.NewScalar()
	delta := l.g.NewScalar()
	for i, pi := range p {
		pol0.Add(pol0, delta.Mul(pi.y, l.basisCoeff(p, i)))
	}

	return pol0
}
