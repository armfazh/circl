package goldilocks

import (
	"encoding/binary"
	"math/bits"
)

// mLSBRecoding parameters
const (
	fxT        = 450
	fxV        = 2
	fxW        = 3
	fx2w1      = 1 << (uint(fxW) - 1)
	numWords64 = 7 // ceil(448/64)
)

// isLessThan returns true if 0 <= x < y, and assumes that slices have the same length.
func isLessThan(x, y []byte) bool {
	i := len(x) - 1
	for i > 0 && x[i] == y[i] {
		i--
	}
	return x[i] < y[i]
}

// mLSBRecoding is the odd-only modified LSB-set.
//
// Reference:
//  "Efficient and secure algorithms for GLV-based scalar multiplication and
//   their implementation on GLV–GLS curves" by (Faz-Hernandez et al.)
//   http://doi.org/10.1007/s13389-014-0085-7
func mLSBRecoding(L []int8, k []byte) {
	const ee = (fxT + fxW*fxV - 1) / (fxW * fxV)
	const dd = ee * fxV
	const ll = dd * fxW
	if len(L) == (ll + 1) {
		var m [numWords64 + 1]uint64
		for i := 0; i < numWords64; i++ {
			m[i] = binary.LittleEndian.Uint64(k[8*i : 8*i+8])
		}
		condAddOrderN(&m)
		L[dd-1] = 1
		for i := 0; i < dd-1; i++ {
			kip1 := (m[(i+1)/64] >> (uint(i+1) % 64)) & 0x1
			L[i] = int8(kip1<<1) - 1
		}
		{ // right-shift by d
			right := uint(dd % 64)
			left := uint(64) - right
			lim := ((numWords64+1)*64 - dd) / 64
			j := dd / 64
			for i := 0; i < lim; i++ {
				m[i] = (m[i+j] >> right) | (m[i+j+1] << left)
			}
			m[lim] = m[lim+j] >> right
		}
		for i := dd; i < ll; i++ {
			L[i] = L[i%dd] * int8(m[0]&0x1)
			div2subY(m[:], int64(L[i]>>1), numWords64)
		}
		L[ll] = int8(m[0])
	}
}

// absolute returns always a positive value.
func absolute(x int32) int32 {
	mask := x >> 31
	return (x + mask) ^ mask
}

// condAddOrderN updates x = x+order if x is even, otherwise x remains unchanged
func condAddOrderN(x *[numWords64 + 1]uint64) {
	isOdd := (x[0] & 0x1) - 1
	c := uint64(0)
	for i := 0; i < numWords64; i++ {
		orderWord := binary.LittleEndian.Uint64(order[8*i : 8*i+8])
		o := isOdd & orderWord
		x0, c0 := bits.Add64(x[i], o, c)
		x[i] = x0
		c = c0
	}
	x[numWords64], _ = bits.Add64(x[numWords64], 0, c)
}

// div2subY update x = (x/2) - y
func div2subY(x []uint64, y int64, l int) {
	s := uint64(y >> 63)
	for i := 0; i < l-1; i++ {
		x[i] = (x[i] >> 1) | (x[i+1] << 63)
	}
	x[l-1] = (x[l-1] >> 1)

	b := uint64(0)
	x0, b0 := bits.Sub64(x[0], uint64(y), b)
	x[0] = x0
	b = b0
	for i := 1; i < l-1; i++ {
		x0, b0 := bits.Sub64(x[i], s, b)
		x[i] = x0
		b = b0
	}
	x[l-1], _ = bits.Sub64(x[l-1], s, b)
}
