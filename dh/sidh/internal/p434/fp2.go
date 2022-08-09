// Code generated by go generate; DO NOT EDIT.
// This file was generated by robots.

package p434

import (
	"github.com/cloudflare/circl/dh/sidh/internal/common"
)

// Montgomery multiplication. Input values must be already
// in Montgomery domain.
func mulP(dest, lhs, rhs *common.Fp) {
	var ab common.FpX2
	mulP434(&ab, lhs, rhs) // = a*b*R*R
	rdcP434(dest, &ab)     // = a*b*R mod p
}

// Set dest = x^((p-3)/4).  If x is square, this is 1/sqrt(x).
// Uses variation of sliding-window algorithm from with window size
// of 5 and least to most significant bit sliding (left-to-right)
// See HAC 14.85 for general description.
//
// Allowed to overlap x with dest.
// All values in Montgomery domains
// Set dest = x^(2^k), for k >= 1, by repeated squarings.
func p34(dest, x *common.Fp) {
	var lookup [16]common.Fp

	// This performs sum(powStrategy) + 1 squarings and len(lookup) + len(mulStrategy)
	// multiplications.
	powStrategy := []uint8{3, 10, 7, 5, 6, 5, 3, 8, 4, 7, 5, 6, 4, 5, 9, 6, 3, 11, 5, 5, 2, 8, 4, 7, 7, 8, 5, 6, 4, 8, 5, 2, 10, 6, 5, 4, 8, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 1}
	mulStrategy := []uint8{2, 15, 9, 8, 14, 12, 2, 8, 5, 15, 8, 15, 6, 6, 3, 2, 0, 10, 9, 13, 1, 12, 3, 7, 1, 10, 8, 11, 2, 15, 14, 1, 11, 12, 14, 3, 11, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 0}
	initialMul := uint8(8)

	// Precompute lookup table of odd multiples of x for window
	// size k=5.
	var xx common.Fp
	mulP(&xx, x, x)
	lookup[0] = *x
	for i := 1; i < 16; i++ {
		mulP(&lookup[i], &lookup[i-1], &xx)
	}

	// Now lookup = {x, x^3, x^5, ... }
	// so that lookup[i] = x^{2*i + 1}
	// so that lookup[k/2] = x^k, for odd k
	*dest = lookup[initialMul]
	for i := uint8(0); i < uint8(len(powStrategy)); i++ {
		mulP(dest, dest, dest)
		for j := uint8(1); j < powStrategy[i]; j++ {
			mulP(dest, dest, dest)
		}
		mulP(dest, dest, &lookup[mulStrategy[i]])
	}
}

func add(dest, lhs, rhs *common.Fp2) {
	addP434(&dest.A, &lhs.A, &rhs.A)
	addP434(&dest.B, &lhs.B, &rhs.B)
}

func sub(dest, lhs, rhs *common.Fp2) {
	subP434(&dest.A, &lhs.A, &rhs.A)
	subP434(&dest.B, &lhs.B, &rhs.B)
}

func mul(dest, lhs, rhs *common.Fp2) {
	var bMinA, cMinD common.Fp
	var ac, bd common.FpX2
	var adPlusBc common.FpX2
	var acMinBd common.FpX2

	// Let (a,b,c,d) = (lhs.a,lhs.b,rhs.a,rhs.b).
	//
	// (a + bi)*(c + di) = (a*c - b*d) + (a*d + b*c)i
	//
	// Use Karatsuba's trick: note that
	//
	// (b - a)*(c - d) = (b*c + a*d) - a*c - b*d
	//
	// so (a*d + b*c) = (b-a)*(c-d) + a*c + b*d.
	mulP434(&ac, &lhs.A, &rhs.A)       // = a*c*R*R
	mulP434(&bd, &lhs.B, &rhs.B)       // = b*d*R*R
	subP434(&bMinA, &lhs.B, &lhs.A)    // = (b-a)*R
	subP434(&cMinD, &rhs.A, &rhs.B)    // = (c-d)*R
	mulP434(&adPlusBc, &bMinA, &cMinD) // = (b-a)*(c-d)*R*R
	adlP434(&adPlusBc, &adPlusBc, &ac) // = ((b-a)*(c-d) + a*c)*R*R
	adlP434(&adPlusBc, &adPlusBc, &bd) // = ((b-a)*(c-d) + a*c + b*d)*R*R
	rdcP434(&dest.B, &adPlusBc)        // = (a*d + b*c)*R mod p
	sulP434(&acMinBd, &ac, &bd)        // = (a*c - b*d)*R*R
	rdcP434(&dest.A, &acMinBd)         // = (a*c - b*d)*R mod p
}

// Set dest = 1/x
//
// Allowed to overlap dest with x.
//
// Returns dest to allow chaining operations.
func inv(dest, x *common.Fp2) {
	var e1, e2 common.FpX2
	var f1, f2 common.Fp

	// We want to compute
	//
	//    1          1     (a - bi)	    (a - bi)
	// -------- = -------- -------- = -----------
	// (a + bi)   (a + bi) (a - bi)   (a^2 + b^2)
	//
	// Letting c = 1/(a^2 + b^2), this is
	//
	// 1/(a+bi) = a*c - b*ci.

	mulP434(&e1, &x.A, &x.A) // = a*a*R*R
	mulP434(&e2, &x.B, &x.B) // = b*b*R*R
	adlP434(&e1, &e1, &e2)   // = (a^2 + b^2)*R*R
	rdcP434(&f1, &e1)        // = (a^2 + b^2)*R mod p
	// Now f1 = a^2 + b^2

	mulP(&f2, &f1, &f1)
	p34(&f2, &f2)
	mulP(&f2, &f2, &f2)
	mulP(&f2, &f2, &f1)

	mulP434(&e1, &x.A, &f2)
	rdcP434(&dest.A, &e1)

	subP434(&f1, &common.Fp{}, &x.B)
	mulP434(&e1, &f1, &f2)
	rdcP434(&dest.B, &e1)
}

func sqr(dest, x *common.Fp2) {
	var a2, aPlusB, aMinusB common.Fp
	var a2MinB2, ab2 common.FpX2

	a := &x.A
	b := &x.B

	// (a + bi)*(a + bi) = (a^2 - b^2) + 2abi.
	addP434(&a2, a, a)                   // = a*R + a*R = 2*a*R
	addP434(&aPlusB, a, b)               // = a*R + b*R = (a+b)*R
	subP434(&aMinusB, a, b)              // = a*R - b*R = (a-b)*R
	mulP434(&a2MinB2, &aPlusB, &aMinusB) // = (a+b)*(a-b)*R*R = (a^2 - b^2)*R*R
	mulP434(&ab2, &a2, b)                // = 2*a*b*R*R
	rdcP434(&dest.A, &a2MinB2)           // = (a^2 - b^2)*R mod p
	rdcP434(&dest.B, &ab2)               // = 2*a*b*R mod p
}

// In case choice == 1, performs following swap in constant time:
//
// xPx <-> xQx
// xPz <-> xQz
//
// Otherwise returns xPx, xPz, xQx, xQz unchanged
func cswap(xPx, xPz, xQx, xQz *common.Fp2, choice uint8) {
	cswapP434(&xPx.A, &xQx.A, choice)
	cswapP434(&xPx.B, &xQx.B, choice)
	cswapP434(&xPz.A, &xQz.A, choice)
	cswapP434(&xPz.B, &xQz.B, choice)
}

// In case choice == 1, performs following moves in constant time:
//
// xPx <- xQx
// xPz <- xQz
//
// Otherwise returns xPx, xPz, xQx, xQz unchanged
func cmov(xPx, xPz, xQx, xQz *common.Fp2, choice uint8) {
	cmovP434(&xPx.A, &xQx.A, choice)
	cmovP434(&xPx.B, &xQx.B, choice)
	cmovP434(&xPz.A, &xQz.A, choice)
	cmovP434(&xPz.B, &xQz.B, choice)
}

func isZero(x *common.Fp2) uint8 {
	r64 := uint64(0)
	for i := 0; i < FpWords; i++ {
		r64 |= x.A[i] | x.B[i]
	}
	r := uint8(0)
	for i := uint64(0); i < 64; i++ {
		r |= uint8((r64 >> i) & 0x1)
	}
	return 1 - r
}

// Converts in.A and in.B to Montgomery domain and stores
// in 'out'
// out.A = in.A * R mod p
// out.B = in.B * R mod p
// Performs v = v*R^2*R^(-1) mod p, for both in.A and in.B
func ToMontgomery(out, in *common.Fp2) {
	var aRR common.FpX2

	// a*R*R
	mulP434(&aRR, &in.A, &P434R2)
	// a*R mod p
	rdcP434(&out.A, &aRR)
	mulP434(&aRR, &in.B, &P434R2)
	rdcP434(&out.B, &aRR)
}

// Converts in.A and in.B from Montgomery domain and stores
// in 'out'
// out.A = in.A mod p
// out.B = in.B mod p
//
// After returning from the call 'in' is not modified.
func FromMontgomery(out, in *common.Fp2) {
	var aR common.FpX2

	// convert from montgomery domain
	copy(aR[:], in.A[:])
	rdcP434(&out.A, &aR) // = a mod p in [0, 2p)
	modP434(&out.A)      // = a mod p in [0, p)
	for i := range aR {
		aR[i] = 0
	}
	copy(aR[:], in.B[:])
	rdcP434(&out.B, &aR)
	modP434(&out.B)
}
