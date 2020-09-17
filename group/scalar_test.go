package group_test

import (
	"fmt"
	"testing"

	"github.com/cloudflare/circl/group"
)

func BenchmarkScalar(b *testing.B) {
	for _, id := range []group.GroupID{
		group.P256,
		group.P384,
		group.P521,
	} {
		g := group.NewGroup(id)
		x := g.RandomScalar(nil)
		y := g.RandomScalar(nil)
		z := g.RandomScalar(nil)
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
