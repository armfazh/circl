package internal

// An element of our base ring R which are polynomials over Z_q modulo
// the equation X^N = -1, where q=2^23 - 2^13 + 1 and N=256.
//
// Coefficients aren't always reduced.  See Freeze()
type Poly [N]uint32

// Reduces each of the coefficients to <2q.
func (p *Poly) ReduceLe2Q() {
	for i := uint(0); i < N; i++ {
		p[i] = reduceLe2Q(p[i])
	}
}

// Reduce each of the coefficients to <q.
func (p *Poly) Normalize() {
	for i := uint(0); i < N; i++ {
		p[i] = modQ(p[i])
	}
}

// Normalize the coefficients in this polynomial assuming they are already
// bounded by 2q.
func (p *Poly) NormalizeAssumingLe2Q() {
	for i := 0; i < N; i++ {
		p[i] = le2qModQ(p[i])
	}
}

// Sets p to a + b.  Does not normalize polynomials.
func (p *Poly) Add(a, b *Poly) {
	for i := uint(0); i < N; i++ {
		p[i] = a[i] + b[i]
	}
}

// Sets p to a - b.
//
// Warning: assumes coefficients of b are less than 2q.
func (p *Poly) Sub(a, b *Poly) {
	for i := uint(0); i < N; i++ {
		p[i] = a[i] + (2*Q - b[i])
	}
}

// Checks whether the "supnorm" (see sec 2.1 of the spec) of p is equal
// or greater than the given bound.
//
// Requires the coefficients of p to be normalized.
func (p *Poly) Exceeds(bound uint32) bool {
	// Note that we are allowed to leak which coefficients breaks the bound,
	// but not its sign.
	for i := 0; i < N; i++ {
		// The central. reps. of {0,       1, ..., (Q-1)/2,  (Q+1)/2, ..., Q-1}
		// are given by          {0,       1, ..., (Q-1)/2, -(Q-1)/2, ...,  -1}
		// so their norms are    {0,       1, ..., (Q-1)/2l, (Q-1)/2, ...,   1}.
		// We'll compute them in a different way though.

		// Sets x to             {(Q-1)/2, (Q-3)/2, ..., 0, -1, ..., -(Q-1)/2}
		x := int32((Q-1)/2) - int32(p[i])
		// Sets x to             {(Q-1)/2, (Q-3)/2, ..., 0, 0, ...,  (Q-3)/2}
		x ^= (x >> 31)
		// Sets x to             {0,       1, ...,  (Q-1)/2, (Q-1)/2, ..., 1}
		x = int32((Q-1)/2) - x
		if uint32(x) >= bound {
			return true
		}
	}
	return false
}

// Splits each of the coefficients using decompose.
//
// Requires p to be normalized.
func (p *Poly) Decompose(p0PlusQ, p1 *Poly) {
	for i := 0; i < N; i++ {
		p0PlusQ[i], p1[i] = decompose(p[i])
	}
}

// Splits p into p1 and p0 such that [i]p1 * 2^D + [i]p0 = [i]p
// with -2^{D-1} < [i]p0 ≤ 2^{D-1}.  Returns p0 + Q and p1.
//
// Requires the coefficients of p to be normalized.
func (p *Poly) Power2Round(p0PlusQ, p1 *Poly) {
	for i := 0; i < N; i++ {
		p0PlusQ[i], p1[i] = power2round(p[i])
	}
}

// Sets p to the hint polynomail for low part p0 and high part p1.
//
// Returns the number of ones in the hint vector.
func (p *Poly) MakeHint(p0, p1 *Poly) (pop uint32) {
	for i := 0; i < N; i++ {
		h := makeHint(p0[i], p1[i])
		pop += h
		p[i] = h
	}
	return
}

// Computes corrections to the high bits of the polynomial q according
// to the hints in h and sets p to the corrected high bits.  Returns p.
func (p *Poly) UseHint(q, hint *Poly) *Poly {
	for i := 0; i < N; i++ {
		p[i] = useHint(q[i], hint[i])
	}
	return p
}

// Sets p to the polynomial whose coefficients are the pointwise multiplication
// of those of a and b.  The coefficients of p are bounded by 2q.
//
// Assumes a and b are in Montgomery form and that the pointwise product
// of each coefficient is below 2^32 q.
func (p *Poly) MulHat(a, b *Poly) {
	for i := 0; i < N; i++ {
		p[i] = montReduceLe2Q(uint64(a[i]) * uint64(b[i]))
	}
}

// Sets p to 2^d q without reducing.
//
// So it requires the coefficients of p  to be less than 2^{32-D}.
func (p *Poly) MulBy2toD(q *Poly) {
	for i := 0; i < N; i++ {
		p[i] = q[i] << D
	}
}
