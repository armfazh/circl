package pog_test

import (
	"fmt"
	"testing"

	"github.com/cloudflare/circl/pog"
)

func BenchmarkPog(b *testing.B) {
	for _, id := range []pog.GID{
		pog.P256,
		pog.P384,
		pog.P521,
	} {
		g := pog.NewGroup(id)
		x := g.RandomEE(nil)
		y := g.RandomEE(nil)
		n := g.RandomSC(nil)
		name := g.(fmt.Stringer).String()
		b.Run(name+"/Add", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				x = g.Add(x, y)
			}
		})
		b.Run(name+"/Mul", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				x = g.Mul(x, n)
			}
		})
		b.Run(name+"/MulGen", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				g.MulGen(n)
			}
		})
	}
}
