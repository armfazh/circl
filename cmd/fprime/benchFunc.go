package main

var addBench = `
func BenchmarkElem(b *testing.B) {
	var x, y, z {{.Cfg.PkgName}}.Elem
	x.Rand(rand.Reader)
	y.Rand(rand.Reader)
	z.Rand(rand.Reader)

	b.Run("Add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			z.Add(&x, &y)
		}
	})
	b.Run("Sub", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			z.Sub(&x, &y)
		}
	})
	b.Run("Mul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			z.Mul(&x, &y)
		}
	})
    b.Run("Sqr", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			z.Sqr(&x)
		}
	})
    b.Run("Inv", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			z.Inv(&x)
		}
	})
}`
