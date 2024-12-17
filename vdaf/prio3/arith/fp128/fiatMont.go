// Code generated by fiat.go using fiat-crypto v0.1.4.
//
// Autogenerated: './FiatCrypto_v.0.1.4-issue1672' word-by-word-montgomery --output 'fp128/fiatMont.go' --lang Go --package-name fp128 --doc-prepend-header 'Code generated by fiat.go using fiat-crypto v0.1.4.' --package-case lowerCamelCase --public-function-case lowerCamelCase --public-type-case lowerCamelCase --doc-newline-before-package-declaration --no-primitives --widen-carry --no-field-element-typedefs --relax-primitive-carry-to-bitwidth 64 Fp 64 0xffffffffffffffe40000000000000001 add sub mul square
//
// curve description: Fp
//
// machine_wordsize = 64 (from "64")
//
// requested operations: add, sub, mul, square
//
// m = 0xffffffffffffffe40000000000000001 (from "0xffffffffffffffe40000000000000001")
//
//
//
// NOTE: In addition to the bounds specified above each function, all
//
//   functions synthesized for this Montgomery arithmetic require the
//
//   input to be strictly less than the prime modulus (m), and also
//
//   require the input to be in the unique saturated representation.
//
//   All functions also ensure that these two properties are true of
//
//   return values.
//
//
//
// Computed values:
//
//   eval z = z[0] + (z[1] << 64)
//
//   bytes_eval z = z[0] + (z[1] << 8) + (z[2] << 16) + (z[3] << 24) + (z[4] << 32) + (z[5] << 40) + (z[6] << 48) + (z[7] << 56) + (z[8] << 64) + (z[9] << 72) + (z[10] << 80) + (z[11] << 88) + (z[12] << 96) + (z[13] << 104) + (z[14] << 112) + (z[15] << 120)
//
//   twos_complement_eval z = let x1 := z[0] + (z[1] << 64) in
//
//                            if x1 & (2^128-1) < 2^127 then x1 & (2^128-1) else (x1 & (2^128-1)) - 2^128

package fp128

import "math/bits"

// The function fiatFpAdd adds two field elements in the Montgomery domain.
//
// Preconditions:
//   0 ≤ eval arg1 < m
//   0 ≤ eval arg2 < m
// Postconditions:
//   eval (from_montgomery out1) mod m = (eval (from_montgomery arg1) + eval (from_montgomery arg2)) mod m
//   0 ≤ eval out1 < m
//
// Input Bounds:
//   arg1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
//   arg2: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
// Output Bounds:
//   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
func fiatFpAdd(out1 *Fp, arg1 *Fp, arg2 *Fp) {
	var x1 uint64
	var x2 uint64
	x1, x2 = bits.Add64(arg1[0], arg2[0], uint64(0x0))
	var x3 uint64
	var x4 uint64
	x3, x4 = bits.Add64(arg1[1], arg2[1], uint64(x2))
	var x5 uint64
	var x6 uint64
	x5, x6 = bits.Sub64(x1, 0x1, uint64(uint64(0x0)))
	var x7 uint64
	var x8 uint64
	x7, x8 = bits.Sub64(x3, 0xffffffffffffffe4, uint64(x6))
	var x10 uint64
	_, x10 = bits.Sub64(x4, uint64(0x0), uint64(x8))
	var x11 uint64
	fiatFpCmovznzU64(&x11, x10, x5, x1)
	var x12 uint64
	fiatFpCmovznzU64(&x12, x10, x7, x3)
	out1[0] = x11
	out1[1] = x12
}

// The function fiatFpSub subtracts two field elements in the Montgomery domain.
//
// Preconditions:
//   0 ≤ eval arg1 < m
//   0 ≤ eval arg2 < m
// Postconditions:
//   eval (from_montgomery out1) mod m = (eval (from_montgomery arg1) - eval (from_montgomery arg2)) mod m
//   0 ≤ eval out1 < m
//
// Input Bounds:
//   arg1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
//   arg2: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
// Output Bounds:
//   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
func fiatFpSub(out1 *Fp, arg1 *Fp, arg2 *Fp) {
	x1 := arg2[1]
	x2 := arg2[0]
	var x3 uint64
	var x4 uint64
	x3, x4 = bits.Sub64(arg1[0], x2, uint64(0x0))
	var x5 uint64
	var x6 uint64
	x5, x6 = bits.Sub64(arg1[1], x1, uint64(x4))
	var x7 uint64
	fiatFpCmovznzU64(&x7, x6, uint64(0x0), 0xffffffffffffffff)
	var x8 uint64
	var x9 uint64
	x8, x9 = bits.Add64(x3, (x7 & 0x1), uint64(0x0))
	var x10 uint64
	x10, _ = bits.Add64(x5, (x7 & 0xffffffffffffffe4), uint64(x9))
	out1[0] = x8
	out1[1] = x10
}

// The function fiatFpMul multiplies two field elements in the Montgomery domain.
//
// Preconditions:
//   0 ≤ eval arg1 < m
//   0 ≤ eval arg2 < m
// Postconditions:
//   eval (from_montgomery out1) mod m = (eval (from_montgomery arg1) * eval (from_montgomery arg2)) mod m
//   0 ≤ eval out1 < m
//
// Input Bounds:
//   arg1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
//   arg2: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
// Output Bounds:
//   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
func fiatFpMul(out1 *Fp, arg1 *Fp, arg2 *Fp) {
	x1 := arg1[1]
	x2 := arg1[0]
	var x3 uint64
	var x4 uint64
	x4, x3 = bits.Mul64(x2, arg2[1])
	var x5 uint64
	var x6 uint64
	x6, x5 = bits.Mul64(x2, arg2[0])
	var x7 uint64
	var x8 uint64
	x7, x8 = bits.Add64(x6, x3, uint64(0x0))
	x9 := (x8 + x4)
	var x10 uint64
	_, x10 = bits.Mul64(x5, 0xffffffffffffffff)
	var x12 uint64
	var x13 uint64
	x13, x12 = bits.Mul64(x10, 0xffffffffffffffe4)
	var x15 uint64
	_, x15 = bits.Add64(x5, x10, uint64(0x0))
	var x16 uint64
	var x17 uint64
	x16, x17 = bits.Add64(x7, x12, uint64(x15))
	var x18 uint64
	var x19 uint64
	x18, x19 = bits.Add64(x9, x13, uint64(x17))
	var x20 uint64
	var x21 uint64
	x21, x20 = bits.Mul64(x1, arg2[1])
	var x22 uint64
	var x23 uint64
	x23, x22 = bits.Mul64(x1, arg2[0])
	var x24 uint64
	var x25 uint64
	x24, x25 = bits.Add64(x23, x20, uint64(0x0))
	x26 := (x25 + x21)
	var x27 uint64
	var x28 uint64
	x27, x28 = bits.Add64(x16, x22, uint64(0x0))
	var x29 uint64
	var x30 uint64
	x29, x30 = bits.Add64(x18, x24, uint64(x28))
	var x31 uint64
	var x32 uint64
	x31, x32 = bits.Add64(x19, x26, uint64(x30))
	var x33 uint64
	_, x33 = bits.Mul64(x27, 0xffffffffffffffff)
	var x35 uint64
	var x36 uint64
	x36, x35 = bits.Mul64(x33, 0xffffffffffffffe4)
	var x38 uint64
	_, x38 = bits.Add64(x27, x33, uint64(0x0))
	var x39 uint64
	var x40 uint64
	x39, x40 = bits.Add64(x29, x35, uint64(x38))
	var x41 uint64
	var x42 uint64
	x41, x42 = bits.Add64(x31, x36, uint64(x40))
	x43 := (x42 + x32)
	var x44 uint64
	var x45 uint64
	x44, x45 = bits.Sub64(x39, 0x1, uint64(uint64(0x0)))
	var x46 uint64
	var x47 uint64
	x46, x47 = bits.Sub64(x41, 0xffffffffffffffe4, uint64(x45))
	var x49 uint64
	_, x49 = bits.Sub64(x43, uint64(0x0), uint64(x47))
	var x50 uint64
	fiatFpCmovznzU64(&x50, x49, x44, x39)
	var x51 uint64
	fiatFpCmovznzU64(&x51, x49, x46, x41)
	out1[0] = x50
	out1[1] = x51
}

// The function fiatFpSquare squares a field element in the Montgomery domain.
//
// Preconditions:
//   0 ≤ eval arg1 < m
// Postconditions:
//   eval (from_montgomery out1) mod m = (eval (from_montgomery arg1) * eval (from_montgomery arg1)) mod m
//   0 ≤ eval out1 < m
//
// Input Bounds:
//   arg1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
// Output Bounds:
//   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
func fiatFpSquare(out1 *Fp, arg1 *Fp) {
	x1 := arg1[1]
	x2 := arg1[0]
	var x3 uint64
	var x4 uint64
	x4, x3 = bits.Mul64(x2, arg1[1])
	var x5 uint64
	var x6 uint64
	x6, x5 = bits.Mul64(x2, arg1[0])
	var x7 uint64
	var x8 uint64
	x7, x8 = bits.Add64(x6, x3, uint64(0x0))
	x9 := (x8 + x4)
	var x10 uint64
	_, x10 = bits.Mul64(x5, 0xffffffffffffffff)
	var x12 uint64
	var x13 uint64
	x13, x12 = bits.Mul64(x10, 0xffffffffffffffe4)
	var x15 uint64
	_, x15 = bits.Add64(x5, x10, uint64(0x0))
	var x16 uint64
	var x17 uint64
	x16, x17 = bits.Add64(x7, x12, uint64(x15))
	var x18 uint64
	var x19 uint64
	x18, x19 = bits.Add64(x9, x13, uint64(x17))
	var x20 uint64
	var x21 uint64
	x21, x20 = bits.Mul64(x1, arg1[1])
	var x22 uint64
	var x23 uint64
	x23, x22 = bits.Mul64(x1, arg1[0])
	var x24 uint64
	var x25 uint64
	x24, x25 = bits.Add64(x23, x20, uint64(0x0))
	x26 := (x25 + x21)
	var x27 uint64
	var x28 uint64
	x27, x28 = bits.Add64(x16, x22, uint64(0x0))
	var x29 uint64
	var x30 uint64
	x29, x30 = bits.Add64(x18, x24, uint64(x28))
	var x31 uint64
	var x32 uint64
	x31, x32 = bits.Add64(x19, x26, uint64(x30))
	var x33 uint64
	_, x33 = bits.Mul64(x27, 0xffffffffffffffff)
	var x35 uint64
	var x36 uint64
	x36, x35 = bits.Mul64(x33, 0xffffffffffffffe4)
	var x38 uint64
	_, x38 = bits.Add64(x27, x33, uint64(0x0))
	var x39 uint64
	var x40 uint64
	x39, x40 = bits.Add64(x29, x35, uint64(x38))
	var x41 uint64
	var x42 uint64
	x41, x42 = bits.Add64(x31, x36, uint64(x40))
	x43 := (x42 + x32)
	var x44 uint64
	var x45 uint64
	x44, x45 = bits.Sub64(x39, 0x1, uint64(uint64(0x0)))
	var x46 uint64
	var x47 uint64
	x46, x47 = bits.Sub64(x41, 0xffffffffffffffe4, uint64(x45))
	var x49 uint64
	_, x49 = bits.Sub64(x43, uint64(0x0), uint64(x47))
	var x50 uint64
	fiatFpCmovznzU64(&x50, x49, x44, x39)
	var x51 uint64
	fiatFpCmovznzU64(&x51, x49, x46, x41)
	out1[0] = x50
	out1[1] = x51
}
