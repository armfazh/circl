package secretsharing

import (
	"testing"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/internal/test"
)

func TestPolyEval(t *testing.T) {
	g := group.P256
	p := polynomial{2, []group.Scalar{
		g.NewScalar(),
		g.NewScalar(),
		g.NewScalar(),
	}}
	p.coeff[0].SetUint64(5)
	p.coeff[1].SetUint64(5)
	p.coeff[2].SetUint64(2)

	x := g.NewScalar()
	x.SetUint64(10)

	got := p.Evaluate(x)

	want := g.NewScalar()
	want.SetUint64(255)
	if !got.IsEqual(want) {
		test.ReportError(t, got, want)
	}
}

func TestLagrange(t *testing.T) {
	g := group.P256
	p := polynomial{2, []group.Scalar{
		g.NewScalar(),
		g.NewScalar(),
		g.NewScalar(),
	}}
	p.coeff[0].SetUint64(1234)
	p.coeff[1].SetUint64(166)
	p.coeff[2].SetUint64(94)

	pp := []point{
		point{x: g.NewScalar(), y: g.NewScalar()},
		point{x: g.NewScalar(), y: g.NewScalar()},
		point{x: g.NewScalar(), y: g.NewScalar()},
	}
	pp[0].x.SetUint64(2)
	pp[0].y.SetUint64(1942)
	pp[1].x.SetUint64(4)
	pp[1].y.SetUint64(3402)
	pp[2].x.SetUint64(5)
	pp[2].y.SetUint64(4414)

	got, err := lagrangeInterpolate(g, pp)
	test.CheckNoErr(t, err, "failed interpolation")
	want := p.coeff[0]

	if !got.IsEqual(want) {
		test.ReportError(t, got, want)
	}
}
