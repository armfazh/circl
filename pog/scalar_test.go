package pog_test

import (
	"fmt"
	"testing"

	"github.com/cloudflare/circl/pog"
)

func BenchmarkScalar(b *testing.B) {
	for _, id := range []pog.GID{
		pog.P256,
		pog.P384,
		pog.P521,
	} {
		g := pog.NewGroup(id)
		x := g.RandomSC(nil)
		y := g.RandomSC(nil)
		z := g.RandomSC(nil)
		name := g.(fmt.Stringer).String()
		b.Run(name+"/Add", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				z.Add(x, y)
			}
		})
		b.Run(name+"/Mul", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				z.Mul(x, y)
			}
		})
		b.Run(name+"/Inv", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				z.Inv(x)
			}
		})
	}
}
