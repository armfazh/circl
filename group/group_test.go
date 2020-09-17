package group_test

import (
	"fmt"
	"testing"

	"github.com/cloudflare/circl/group"
)

func BenchmarkPog(b *testing.B) {
	for _, id := range []group.GroupID{
		group.P256,
		group.P384,
		group.P521,
	} {
		g := group.NewGroup(id)
		x := g.RandomElement(nil)
		y := g.RandomElement(nil)
		n := g.RandomScalar(nil)
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
