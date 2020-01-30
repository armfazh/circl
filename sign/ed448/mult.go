package ed448

import (
	"crypto/subtle"
	"encoding/binary"
	"math/bits"

	"github.com/cloudflare/circl/internal/conv"
	"github.com/cloudflare/circl/math"
	fp "github.com/cloudflare/circl/math/fp448"
)

var curve = struct {
	order              [Size]byte
	genX, genY, paramD [fp.Size]byte
}{
	order: [Size]byte{
		0xf3, 0x44, 0x58, 0xab, 0x92, 0xc2, 0x78, 0x23,
		0x55, 0x8f, 0xc5, 0x8d, 0x72, 0xc2, 0x6c, 0x21,
		0x90, 0x36, 0xd6, 0xae, 0x49, 0xdb, 0x4e, 0xc4,
		0xe9, 0x23, 0xca, 0x7c, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
		0x00,
	},
	genX: [fp.Size]byte{
		0x5e, 0xc0, 0x0c, 0xc7, 0x2b, 0xa8, 0x26, 0x26,
		0x8e, 0x93, 0x00, 0x8b, 0xe1, 0x80, 0x3b, 0x43,
		0x11, 0x65, 0xb6, 0x2a, 0xf7, 0x1a, 0xae, 0x12,
		0x64, 0xa4, 0xd3, 0xa3, 0x24, 0xe3, 0x6d, 0xea,
		0x67, 0x17, 0x0f, 0x47, 0x70, 0x65, 0x14, 0x9e,
		0xda, 0x36, 0xbf, 0x22, 0xa6, 0x15, 0x1d, 0x22,
		0xed, 0x0d, 0xed, 0x6b, 0xc6, 0x70, 0x19, 0x4f,
	},
	genY: [fp.Size]byte{
		0x14, 0xfa, 0x30, 0xf2, 0x5b, 0x79, 0x08, 0x98,
		0xad, 0xc8, 0xd7, 0x4e, 0x2c, 0x13, 0xbd, 0xfd,
		0xc4, 0x39, 0x7c, 0xe6, 0x1c, 0xff, 0xd3, 0x3a,
		0xd7, 0xc2, 0xa0, 0x05, 0x1e, 0x9c, 0x78, 0x87,
		0x40, 0x98, 0xa3, 0x6c, 0x73, 0x73, 0xea, 0x4b,
		0x62, 0xc7, 0xc9, 0x56, 0x37, 0x20, 0x76, 0x88,
		0x24, 0xbc, 0xb6, 0x6e, 0x71, 0x46, 0x3f, 0x69,
	},
	paramD: [fp.Size]byte{
		0x56, 0x67, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	},
}

// mLSBRecoding parameters
const (
	fxT        = 450
	fxV        = 2
	fxW        = 3
	fx2w1      = 1 << (uint(fxW) - 1)
	numWords64 = (Size * 8 / 64)
)

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
			div2subY(m[:], int64(L[i]>>1), 4)
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
		orderWord := binary.LittleEndian.Uint64(curve.order[8*i : 8*i+8])
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

func (P *pointR1) fixedMult(scalar []byte) {
	if len(scalar) != Size {
		panic("wrong scalar size")
	}
	const ee = (fxT + fxW*fxV - 1) / (fxW * fxV)
	const dd = ee * fxV
	const ll = dd * fxW

	L := make([]int8, ll+1)
	mLSBRecoding(L[:], scalar)
	S := &pointR3{}
	P.SetIdentity()
	for ii := ee - 1; ii >= 0; ii-- {
		P.double()
		for j := 0; j < fxV; j++ {
			dig := L[fxW*dd-j*ee+ii-ee]
			for i := (fxW-1)*dd - j*ee + ii - ee; i >= (2*dd - j*ee + ii - ee); i = i - dd {
				dig = 2*dig + L[i]
			}
			idx := absolute(int32(dig))
			sig := L[dd-j*ee+ii-ee]
			Tabj := &tabSign[fxV-j-1]
			for k := 0; k < fx2w1; k++ {
				S.cmov(&Tabj[k], subtle.ConstantTimeEq(int32(k), idx))
			}
			S.cneg(subtle.ConstantTimeEq(int32(sig), -1))
			P.mixAdd(S)
		}
	}
}

const (
	omegaFix = 7
	omegaVar = 5
)

// doubleMult returns P=mQ+nG
func (P *pointR1) doubleMult(Q *pointR1, m, n []byte) {
	nafFix := math.OmegaNAF(conv.BytesLe2BigInt(m), omegaFix)
	nafVar := math.OmegaNAF(conv.BytesLe2BigInt(n), omegaVar)

	if len(nafFix) > len(nafVar) {
		nafVar = append(nafVar, make([]int32, len(nafFix)-len(nafVar))...)
	} else if len(nafFix) < len(nafVar) {
		nafFix = append(nafFix, make([]int32, len(nafVar)-len(nafFix))...)
	}

	var TabQ [1 << (omegaVar - 2)]pointR2
	Q.oddMultiples(TabQ[:])
	P.SetIdentity()
	for i := len(nafFix) - 1; i >= 0; i-- {
		P.double()
		// Generator point
		if nafFix[i] != 0 {
			idxM := absolute(nafFix[i]) >> 1
			R := tabVerif[idxM]
			if nafFix[i] < 0 {
				R.neg()
			}
			P.mixAdd(&R)
		}
		// Variable input point
		if nafVar[i] != 0 {
			idxN := absolute(nafVar[i]) >> 1
			S := TabQ[idxN]
			if nafVar[i] < 0 {
				S.neg()
			}
			P.add(&S)
		}
	}
}
