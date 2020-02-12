package internal

import (
	common "github.com/cloudflare/circl/sign/dilithium/internal"
)

// A k by l matrix of polynomials.
type Mat [K]VecL

// Expands the given seed to a complete matrix.
//
// This function is called ExpandA in the specification.
func (m *Mat) Derive(seed *[32]byte) {
	for i := uint16(0); i < K; i++ {
		for j := uint16(0); j < L; j++ {
			PolyDeriveUniform(&m[i][j], seed, (i<<8)+j)
		}
	}
}

// Set p to the inner product of a and b using pointwise multiplication.
//
// Assumes a and b are in Montgomery form and their coeffients are
// pairwise sufficiently small to add, see Poly.MulHat().  Resulting
// coefficients are bounded by 2Lq.
func PolyDotHat(p *common.Poly, a, b *VecL) {
	var t common.Poly
	*p = common.Poly{} // zero p
	for i := 0; i < L; i++ {
		t.MulHat(&a[i], &b[i])
		p.Add(&t, p)
	}
}
