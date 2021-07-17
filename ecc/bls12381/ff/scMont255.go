// Code generated by gen.go using fiat-crypto.
//
// Autogenerated: './word_by_word_montgomery' --output scMont255.go --lang Go --package-name ff --doc-prepend-header 'Code generated by gen.go using fiat-crypto.' --package-case lowerCamelCase --public-function-case lowerCamelCase --public-type-case lowerCamelCase --doc-newline-before-package-declaration --cmovznz-by-mul ScMont 64 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001 add sub mul square
//
// curve description: ScMont
//
// machine_wordsize = 64 (from "64")
//
// requested operations: add, sub, mul, square
//
// m = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001 (from "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001")
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
//   eval z = z[0] + (z[1] << 64) + (z[2] << 128) + (z[3] << 192)
//
//   bytes_eval z = z[0] + (z[1] << 8) + (z[2] << 16) + (z[3] << 24) + (z[4] << 32) + (z[5] << 40) + (z[6] << 48) + (z[7] << 56) + (z[8] << 64) + (z[9] << 72) + (z[10] << 80) + (z[11] << 88) + (z[12] << 96) + (z[13] << 104) + (z[14] << 112) + (z[15] << 120) + (z[16] << 128) + (z[17] << 136) + (z[18] << 144) + (z[19] << 152) + (z[20] << 160) + (z[21] << 168) + (z[22] << 176) + (z[23] << 184) + (z[24] << 192) + (z[25] << 200) + (z[26] << 208) + (z[27] << 216) + (z[28] << 224) + (z[29] << 232) + (z[30] << 240) + (z[31] << 248)
//
//   twos_complement_eval z = let x1 := z[0] + (z[1] << 64) + (z[2] << 128) + (z[3] << 192) in
//
//                            if x1 & (2^256-1) < 2^255 then x1 & (2^256-1) else (x1 & (2^256-1)) - 2^256

package ff

import "math/bits"

type fiatScMontUint1 uint8
type fiatScMontInt1 int8

// The function fiatScMontAddcarryxU64 is a thin wrapper around bits.Add64 that uses fiatScMontUint1 rather than uint64
func fiatScMontAddcarryxU64(x uint64, y uint64, carry fiatScMontUint1) (uint64, fiatScMontUint1) {
	sum, carryOut := bits.Add64(x, y, uint64(carry))
	return sum, fiatScMontUint1(carryOut)
}

// The function fiatScMontSubborrowxU64 is a thin wrapper around bits.Sub64 that uses fiatScMontUint1 rather than uint64
func fiatScMontSubborrowxU64(x uint64, y uint64, carry fiatScMontUint1) (uint64, fiatScMontUint1) {
	sum, carryOut := bits.Sub64(x, y, uint64(carry))
	return sum, fiatScMontUint1(carryOut)
}

// The function fiatScMontCmovznzU64 is a single-word conditional move.
//
// Postconditions:
//   out1 = (if arg1 = 0 then arg2 else arg3)
//
// Input Bounds:
//   arg1: [0x0 ~> 0x1]
//   arg2: [0x0 ~> 0xffffffffffffffff]
//   arg3: [0x0 ~> 0xffffffffffffffff]
// Output Bounds:
//   out1: [0x0 ~> 0xffffffffffffffff]
func fiatScMontCmovznzU64(out1 *uint64, arg1 fiatScMontUint1, arg2 uint64, arg3 uint64) {
	x1 := (uint64(arg1) * 0xffffffffffffffff)
	x2 := ((x1 & arg3) | ((^x1) & arg2))
	*out1 = x2
}

// The function fiatScMontAdd adds two field elements in the Montgomery domain.
//
// Preconditions:
//   0 ≤ eval arg1 < m
//   0 ≤ eval arg2 < m
// Postconditions:
//   eval (from_montgomery out1) mod m = (eval (from_montgomery arg1) + eval (from_montgomery arg2)) mod m
//   0 ≤ eval out1 < m
//
// Input Bounds:
//   arg1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
//   arg2: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
// Output Bounds:
//   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
func fiatScMontAdd(out1 *[4]uint64, arg1 *[4]uint64, arg2 *[4]uint64) {
	var x1 uint64
	var x2 fiatScMontUint1
	x1, x2 = fiatScMontAddcarryxU64(arg1[0], arg2[0], 0x0)
	var x3 uint64
	var x4 fiatScMontUint1
	x3, x4 = fiatScMontAddcarryxU64(arg1[1], arg2[1], x2)
	var x5 uint64
	var x6 fiatScMontUint1
	x5, x6 = fiatScMontAddcarryxU64(arg1[2], arg2[2], x4)
	var x7 uint64
	var x8 fiatScMontUint1
	x7, x8 = fiatScMontAddcarryxU64(arg1[3], arg2[3], x6)
	var x9 uint64
	var x10 fiatScMontUint1
	x9, x10 = fiatScMontSubborrowxU64(x1, 0xffffffff00000001, 0x0)
	var x11 uint64
	var x12 fiatScMontUint1
	x11, x12 = fiatScMontSubborrowxU64(x3, 0x53bda402fffe5bfe, x10)
	var x13 uint64
	var x14 fiatScMontUint1
	x13, x14 = fiatScMontSubborrowxU64(x5, 0x3339d80809a1d805, x12)
	var x15 uint64
	var x16 fiatScMontUint1
	x15, x16 = fiatScMontSubborrowxU64(x7, 0x73eda753299d7d48, x14)
	var x18 fiatScMontUint1
	_, x18 = fiatScMontSubborrowxU64(uint64(x8), uint64(0x0), x16)
	var x19 uint64
	fiatScMontCmovznzU64(&x19, x18, x9, x1)
	var x20 uint64
	fiatScMontCmovznzU64(&x20, x18, x11, x3)
	var x21 uint64
	fiatScMontCmovznzU64(&x21, x18, x13, x5)
	var x22 uint64
	fiatScMontCmovznzU64(&x22, x18, x15, x7)
	out1[0] = x19
	out1[1] = x20
	out1[2] = x21
	out1[3] = x22
}

// The function fiatScMontSub subtracts two field elements in the Montgomery domain.
//
// Preconditions:
//   0 ≤ eval arg1 < m
//   0 ≤ eval arg2 < m
// Postconditions:
//   eval (from_montgomery out1) mod m = (eval (from_montgomery arg1) - eval (from_montgomery arg2)) mod m
//   0 ≤ eval out1 < m
//
// Input Bounds:
//   arg1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
//   arg2: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
// Output Bounds:
//   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
func fiatScMontSub(out1 *[4]uint64, arg1 *[4]uint64, arg2 *[4]uint64) {
	var x1 uint64
	var x2 fiatScMontUint1
	x1, x2 = fiatScMontSubborrowxU64(arg1[0], arg2[0], 0x0)
	var x3 uint64
	var x4 fiatScMontUint1
	x3, x4 = fiatScMontSubborrowxU64(arg1[1], arg2[1], x2)
	var x5 uint64
	var x6 fiatScMontUint1
	x5, x6 = fiatScMontSubborrowxU64(arg1[2], arg2[2], x4)
	var x7 uint64
	var x8 fiatScMontUint1
	x7, x8 = fiatScMontSubborrowxU64(arg1[3], arg2[3], x6)
	var x9 uint64
	fiatScMontCmovznzU64(&x9, x8, uint64(0x0), 0xffffffffffffffff)
	var x10 uint64
	var x11 fiatScMontUint1
	x10, x11 = fiatScMontAddcarryxU64(x1, (x9 & 0xffffffff00000001), 0x0)
	var x12 uint64
	var x13 fiatScMontUint1
	x12, x13 = fiatScMontAddcarryxU64(x3, (x9 & 0x53bda402fffe5bfe), x11)
	var x14 uint64
	var x15 fiatScMontUint1
	x14, x15 = fiatScMontAddcarryxU64(x5, (x9 & 0x3339d80809a1d805), x13)
	var x16 uint64
	x16, _ = fiatScMontAddcarryxU64(x7, (x9 & 0x73eda753299d7d48), x15)
	out1[0] = x10
	out1[1] = x12
	out1[2] = x14
	out1[3] = x16
}

// The function fiatScMontMul multiplies two field elements in the Montgomery domain.
//
// Preconditions:
//   0 ≤ eval arg1 < m
//   0 ≤ eval arg2 < m
// Postconditions:
//   eval (from_montgomery out1) mod m = (eval (from_montgomery arg1) * eval (from_montgomery arg2)) mod m
//   0 ≤ eval out1 < m
//
// Input Bounds:
//   arg1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
//   arg2: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
// Output Bounds:
//   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
func fiatScMontMul(out1 *[4]uint64, arg1 *[4]uint64, arg2 *[4]uint64) {
	x1 := arg1[1]
	x2 := arg1[2]
	x3 := arg1[3]
	x4 := arg1[0]
	var x5 uint64
	var x6 uint64
	x6, x5 = bits.Mul64(x4, arg2[3])
	var x7 uint64
	var x8 uint64
	x8, x7 = bits.Mul64(x4, arg2[2])
	var x9 uint64
	var x10 uint64
	x10, x9 = bits.Mul64(x4, arg2[1])
	var x11 uint64
	var x12 uint64
	x12, x11 = bits.Mul64(x4, arg2[0])
	var x13 uint64
	var x14 fiatScMontUint1
	x13, x14 = fiatScMontAddcarryxU64(x12, x9, 0x0)
	var x15 uint64
	var x16 fiatScMontUint1
	x15, x16 = fiatScMontAddcarryxU64(x10, x7, x14)
	var x17 uint64
	var x18 fiatScMontUint1
	x17, x18 = fiatScMontAddcarryxU64(x8, x5, x16)
	x19 := (uint64(x18) + x6)
	var x20 uint64
	_, x20 = bits.Mul64(x11, 0xfffffffeffffffff)
	var x22 uint64
	var x23 uint64
	x23, x22 = bits.Mul64(x20, 0x73eda753299d7d48)
	var x24 uint64
	var x25 uint64
	x25, x24 = bits.Mul64(x20, 0x3339d80809a1d805)
	var x26 uint64
	var x27 uint64
	x27, x26 = bits.Mul64(x20, 0x53bda402fffe5bfe)
	var x28 uint64
	var x29 uint64
	x29, x28 = bits.Mul64(x20, 0xffffffff00000001)
	var x30 uint64
	var x31 fiatScMontUint1
	x30, x31 = fiatScMontAddcarryxU64(x29, x26, 0x0)
	var x32 uint64
	var x33 fiatScMontUint1
	x32, x33 = fiatScMontAddcarryxU64(x27, x24, x31)
	var x34 uint64
	var x35 fiatScMontUint1
	x34, x35 = fiatScMontAddcarryxU64(x25, x22, x33)
	x36 := (uint64(x35) + x23)
	var x38 fiatScMontUint1
	_, x38 = fiatScMontAddcarryxU64(x11, x28, 0x0)
	var x39 uint64
	var x40 fiatScMontUint1
	x39, x40 = fiatScMontAddcarryxU64(x13, x30, x38)
	var x41 uint64
	var x42 fiatScMontUint1
	x41, x42 = fiatScMontAddcarryxU64(x15, x32, x40)
	var x43 uint64
	var x44 fiatScMontUint1
	x43, x44 = fiatScMontAddcarryxU64(x17, x34, x42)
	var x45 uint64
	var x46 fiatScMontUint1
	x45, x46 = fiatScMontAddcarryxU64(x19, x36, x44)
	var x47 uint64
	var x48 uint64
	x48, x47 = bits.Mul64(x1, arg2[3])
	var x49 uint64
	var x50 uint64
	x50, x49 = bits.Mul64(x1, arg2[2])
	var x51 uint64
	var x52 uint64
	x52, x51 = bits.Mul64(x1, arg2[1])
	var x53 uint64
	var x54 uint64
	x54, x53 = bits.Mul64(x1, arg2[0])
	var x55 uint64
	var x56 fiatScMontUint1
	x55, x56 = fiatScMontAddcarryxU64(x54, x51, 0x0)
	var x57 uint64
	var x58 fiatScMontUint1
	x57, x58 = fiatScMontAddcarryxU64(x52, x49, x56)
	var x59 uint64
	var x60 fiatScMontUint1
	x59, x60 = fiatScMontAddcarryxU64(x50, x47, x58)
	x61 := (uint64(x60) + x48)
	var x62 uint64
	var x63 fiatScMontUint1
	x62, x63 = fiatScMontAddcarryxU64(x39, x53, 0x0)
	var x64 uint64
	var x65 fiatScMontUint1
	x64, x65 = fiatScMontAddcarryxU64(x41, x55, x63)
	var x66 uint64
	var x67 fiatScMontUint1
	x66, x67 = fiatScMontAddcarryxU64(x43, x57, x65)
	var x68 uint64
	var x69 fiatScMontUint1
	x68, x69 = fiatScMontAddcarryxU64(x45, x59, x67)
	var x70 uint64
	var x71 fiatScMontUint1
	x70, x71 = fiatScMontAddcarryxU64(uint64(x46), x61, x69)
	var x72 uint64
	_, x72 = bits.Mul64(x62, 0xfffffffeffffffff)
	var x74 uint64
	var x75 uint64
	x75, x74 = bits.Mul64(x72, 0x73eda753299d7d48)
	var x76 uint64
	var x77 uint64
	x77, x76 = bits.Mul64(x72, 0x3339d80809a1d805)
	var x78 uint64
	var x79 uint64
	x79, x78 = bits.Mul64(x72, 0x53bda402fffe5bfe)
	var x80 uint64
	var x81 uint64
	x81, x80 = bits.Mul64(x72, 0xffffffff00000001)
	var x82 uint64
	var x83 fiatScMontUint1
	x82, x83 = fiatScMontAddcarryxU64(x81, x78, 0x0)
	var x84 uint64
	var x85 fiatScMontUint1
	x84, x85 = fiatScMontAddcarryxU64(x79, x76, x83)
	var x86 uint64
	var x87 fiatScMontUint1
	x86, x87 = fiatScMontAddcarryxU64(x77, x74, x85)
	x88 := (uint64(x87) + x75)
	var x90 fiatScMontUint1
	_, x90 = fiatScMontAddcarryxU64(x62, x80, 0x0)
	var x91 uint64
	var x92 fiatScMontUint1
	x91, x92 = fiatScMontAddcarryxU64(x64, x82, x90)
	var x93 uint64
	var x94 fiatScMontUint1
	x93, x94 = fiatScMontAddcarryxU64(x66, x84, x92)
	var x95 uint64
	var x96 fiatScMontUint1
	x95, x96 = fiatScMontAddcarryxU64(x68, x86, x94)
	var x97 uint64
	var x98 fiatScMontUint1
	x97, x98 = fiatScMontAddcarryxU64(x70, x88, x96)
	x99 := (uint64(x98) + uint64(x71))
	var x100 uint64
	var x101 uint64
	x101, x100 = bits.Mul64(x2, arg2[3])
	var x102 uint64
	var x103 uint64
	x103, x102 = bits.Mul64(x2, arg2[2])
	var x104 uint64
	var x105 uint64
	x105, x104 = bits.Mul64(x2, arg2[1])
	var x106 uint64
	var x107 uint64
	x107, x106 = bits.Mul64(x2, arg2[0])
	var x108 uint64
	var x109 fiatScMontUint1
	x108, x109 = fiatScMontAddcarryxU64(x107, x104, 0x0)
	var x110 uint64
	var x111 fiatScMontUint1
	x110, x111 = fiatScMontAddcarryxU64(x105, x102, x109)
	var x112 uint64
	var x113 fiatScMontUint1
	x112, x113 = fiatScMontAddcarryxU64(x103, x100, x111)
	x114 := (uint64(x113) + x101)
	var x115 uint64
	var x116 fiatScMontUint1
	x115, x116 = fiatScMontAddcarryxU64(x91, x106, 0x0)
	var x117 uint64
	var x118 fiatScMontUint1
	x117, x118 = fiatScMontAddcarryxU64(x93, x108, x116)
	var x119 uint64
	var x120 fiatScMontUint1
	x119, x120 = fiatScMontAddcarryxU64(x95, x110, x118)
	var x121 uint64
	var x122 fiatScMontUint1
	x121, x122 = fiatScMontAddcarryxU64(x97, x112, x120)
	var x123 uint64
	var x124 fiatScMontUint1
	x123, x124 = fiatScMontAddcarryxU64(x99, x114, x122)
	var x125 uint64
	_, x125 = bits.Mul64(x115, 0xfffffffeffffffff)
	var x127 uint64
	var x128 uint64
	x128, x127 = bits.Mul64(x125, 0x73eda753299d7d48)
	var x129 uint64
	var x130 uint64
	x130, x129 = bits.Mul64(x125, 0x3339d80809a1d805)
	var x131 uint64
	var x132 uint64
	x132, x131 = bits.Mul64(x125, 0x53bda402fffe5bfe)
	var x133 uint64
	var x134 uint64
	x134, x133 = bits.Mul64(x125, 0xffffffff00000001)
	var x135 uint64
	var x136 fiatScMontUint1
	x135, x136 = fiatScMontAddcarryxU64(x134, x131, 0x0)
	var x137 uint64
	var x138 fiatScMontUint1
	x137, x138 = fiatScMontAddcarryxU64(x132, x129, x136)
	var x139 uint64
	var x140 fiatScMontUint1
	x139, x140 = fiatScMontAddcarryxU64(x130, x127, x138)
	x141 := (uint64(x140) + x128)
	var x143 fiatScMontUint1
	_, x143 = fiatScMontAddcarryxU64(x115, x133, 0x0)
	var x144 uint64
	var x145 fiatScMontUint1
	x144, x145 = fiatScMontAddcarryxU64(x117, x135, x143)
	var x146 uint64
	var x147 fiatScMontUint1
	x146, x147 = fiatScMontAddcarryxU64(x119, x137, x145)
	var x148 uint64
	var x149 fiatScMontUint1
	x148, x149 = fiatScMontAddcarryxU64(x121, x139, x147)
	var x150 uint64
	var x151 fiatScMontUint1
	x150, x151 = fiatScMontAddcarryxU64(x123, x141, x149)
	x152 := (uint64(x151) + uint64(x124))
	var x153 uint64
	var x154 uint64
	x154, x153 = bits.Mul64(x3, arg2[3])
	var x155 uint64
	var x156 uint64
	x156, x155 = bits.Mul64(x3, arg2[2])
	var x157 uint64
	var x158 uint64
	x158, x157 = bits.Mul64(x3, arg2[1])
	var x159 uint64
	var x160 uint64
	x160, x159 = bits.Mul64(x3, arg2[0])
	var x161 uint64
	var x162 fiatScMontUint1
	x161, x162 = fiatScMontAddcarryxU64(x160, x157, 0x0)
	var x163 uint64
	var x164 fiatScMontUint1
	x163, x164 = fiatScMontAddcarryxU64(x158, x155, x162)
	var x165 uint64
	var x166 fiatScMontUint1
	x165, x166 = fiatScMontAddcarryxU64(x156, x153, x164)
	x167 := (uint64(x166) + x154)
	var x168 uint64
	var x169 fiatScMontUint1
	x168, x169 = fiatScMontAddcarryxU64(x144, x159, 0x0)
	var x170 uint64
	var x171 fiatScMontUint1
	x170, x171 = fiatScMontAddcarryxU64(x146, x161, x169)
	var x172 uint64
	var x173 fiatScMontUint1
	x172, x173 = fiatScMontAddcarryxU64(x148, x163, x171)
	var x174 uint64
	var x175 fiatScMontUint1
	x174, x175 = fiatScMontAddcarryxU64(x150, x165, x173)
	var x176 uint64
	var x177 fiatScMontUint1
	x176, x177 = fiatScMontAddcarryxU64(x152, x167, x175)
	var x178 uint64
	_, x178 = bits.Mul64(x168, 0xfffffffeffffffff)
	var x180 uint64
	var x181 uint64
	x181, x180 = bits.Mul64(x178, 0x73eda753299d7d48)
	var x182 uint64
	var x183 uint64
	x183, x182 = bits.Mul64(x178, 0x3339d80809a1d805)
	var x184 uint64
	var x185 uint64
	x185, x184 = bits.Mul64(x178, 0x53bda402fffe5bfe)
	var x186 uint64
	var x187 uint64
	x187, x186 = bits.Mul64(x178, 0xffffffff00000001)
	var x188 uint64
	var x189 fiatScMontUint1
	x188, x189 = fiatScMontAddcarryxU64(x187, x184, 0x0)
	var x190 uint64
	var x191 fiatScMontUint1
	x190, x191 = fiatScMontAddcarryxU64(x185, x182, x189)
	var x192 uint64
	var x193 fiatScMontUint1
	x192, x193 = fiatScMontAddcarryxU64(x183, x180, x191)
	x194 := (uint64(x193) + x181)
	var x196 fiatScMontUint1
	_, x196 = fiatScMontAddcarryxU64(x168, x186, 0x0)
	var x197 uint64
	var x198 fiatScMontUint1
	x197, x198 = fiatScMontAddcarryxU64(x170, x188, x196)
	var x199 uint64
	var x200 fiatScMontUint1
	x199, x200 = fiatScMontAddcarryxU64(x172, x190, x198)
	var x201 uint64
	var x202 fiatScMontUint1
	x201, x202 = fiatScMontAddcarryxU64(x174, x192, x200)
	var x203 uint64
	var x204 fiatScMontUint1
	x203, x204 = fiatScMontAddcarryxU64(x176, x194, x202)
	x205 := (uint64(x204) + uint64(x177))
	var x206 uint64
	var x207 fiatScMontUint1
	x206, x207 = fiatScMontSubborrowxU64(x197, 0xffffffff00000001, 0x0)
	var x208 uint64
	var x209 fiatScMontUint1
	x208, x209 = fiatScMontSubborrowxU64(x199, 0x53bda402fffe5bfe, x207)
	var x210 uint64
	var x211 fiatScMontUint1
	x210, x211 = fiatScMontSubborrowxU64(x201, 0x3339d80809a1d805, x209)
	var x212 uint64
	var x213 fiatScMontUint1
	x212, x213 = fiatScMontSubborrowxU64(x203, 0x73eda753299d7d48, x211)
	var x215 fiatScMontUint1
	_, x215 = fiatScMontSubborrowxU64(x205, uint64(0x0), x213)
	var x216 uint64
	fiatScMontCmovznzU64(&x216, x215, x206, x197)
	var x217 uint64
	fiatScMontCmovznzU64(&x217, x215, x208, x199)
	var x218 uint64
	fiatScMontCmovznzU64(&x218, x215, x210, x201)
	var x219 uint64
	fiatScMontCmovznzU64(&x219, x215, x212, x203)
	out1[0] = x216
	out1[1] = x217
	out1[2] = x218
	out1[3] = x219
}

// The function fiatScMontSquare squares a field element in the Montgomery domain.
//
// Preconditions:
//   0 ≤ eval arg1 < m
// Postconditions:
//   eval (from_montgomery out1) mod m = (eval (from_montgomery arg1) * eval (from_montgomery arg1)) mod m
//   0 ≤ eval out1 < m
//
// Input Bounds:
//   arg1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
// Output Bounds:
//   out1: [[0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff], [0x0 ~> 0xffffffffffffffff]]
func fiatScMontSquare(out1 *[4]uint64, arg1 *[4]uint64) {
	x1 := arg1[1]
	x2 := arg1[2]
	x3 := arg1[3]
	x4 := arg1[0]
	var x5 uint64
	var x6 uint64
	x6, x5 = bits.Mul64(x4, arg1[3])
	var x7 uint64
	var x8 uint64
	x8, x7 = bits.Mul64(x4, arg1[2])
	var x9 uint64
	var x10 uint64
	x10, x9 = bits.Mul64(x4, arg1[1])
	var x11 uint64
	var x12 uint64
	x12, x11 = bits.Mul64(x4, arg1[0])
	var x13 uint64
	var x14 fiatScMontUint1
	x13, x14 = fiatScMontAddcarryxU64(x12, x9, 0x0)
	var x15 uint64
	var x16 fiatScMontUint1
	x15, x16 = fiatScMontAddcarryxU64(x10, x7, x14)
	var x17 uint64
	var x18 fiatScMontUint1
	x17, x18 = fiatScMontAddcarryxU64(x8, x5, x16)
	x19 := (uint64(x18) + x6)
	var x20 uint64
	_, x20 = bits.Mul64(x11, 0xfffffffeffffffff)
	var x22 uint64
	var x23 uint64
	x23, x22 = bits.Mul64(x20, 0x73eda753299d7d48)
	var x24 uint64
	var x25 uint64
	x25, x24 = bits.Mul64(x20, 0x3339d80809a1d805)
	var x26 uint64
	var x27 uint64
	x27, x26 = bits.Mul64(x20, 0x53bda402fffe5bfe)
	var x28 uint64
	var x29 uint64
	x29, x28 = bits.Mul64(x20, 0xffffffff00000001)
	var x30 uint64
	var x31 fiatScMontUint1
	x30, x31 = fiatScMontAddcarryxU64(x29, x26, 0x0)
	var x32 uint64
	var x33 fiatScMontUint1
	x32, x33 = fiatScMontAddcarryxU64(x27, x24, x31)
	var x34 uint64
	var x35 fiatScMontUint1
	x34, x35 = fiatScMontAddcarryxU64(x25, x22, x33)
	x36 := (uint64(x35) + x23)
	var x38 fiatScMontUint1
	_, x38 = fiatScMontAddcarryxU64(x11, x28, 0x0)
	var x39 uint64
	var x40 fiatScMontUint1
	x39, x40 = fiatScMontAddcarryxU64(x13, x30, x38)
	var x41 uint64
	var x42 fiatScMontUint1
	x41, x42 = fiatScMontAddcarryxU64(x15, x32, x40)
	var x43 uint64
	var x44 fiatScMontUint1
	x43, x44 = fiatScMontAddcarryxU64(x17, x34, x42)
	var x45 uint64
	var x46 fiatScMontUint1
	x45, x46 = fiatScMontAddcarryxU64(x19, x36, x44)
	var x47 uint64
	var x48 uint64
	x48, x47 = bits.Mul64(x1, arg1[3])
	var x49 uint64
	var x50 uint64
	x50, x49 = bits.Mul64(x1, arg1[2])
	var x51 uint64
	var x52 uint64
	x52, x51 = bits.Mul64(x1, arg1[1])
	var x53 uint64
	var x54 uint64
	x54, x53 = bits.Mul64(x1, arg1[0])
	var x55 uint64
	var x56 fiatScMontUint1
	x55, x56 = fiatScMontAddcarryxU64(x54, x51, 0x0)
	var x57 uint64
	var x58 fiatScMontUint1
	x57, x58 = fiatScMontAddcarryxU64(x52, x49, x56)
	var x59 uint64
	var x60 fiatScMontUint1
	x59, x60 = fiatScMontAddcarryxU64(x50, x47, x58)
	x61 := (uint64(x60) + x48)
	var x62 uint64
	var x63 fiatScMontUint1
	x62, x63 = fiatScMontAddcarryxU64(x39, x53, 0x0)
	var x64 uint64
	var x65 fiatScMontUint1
	x64, x65 = fiatScMontAddcarryxU64(x41, x55, x63)
	var x66 uint64
	var x67 fiatScMontUint1
	x66, x67 = fiatScMontAddcarryxU64(x43, x57, x65)
	var x68 uint64
	var x69 fiatScMontUint1
	x68, x69 = fiatScMontAddcarryxU64(x45, x59, x67)
	var x70 uint64
	var x71 fiatScMontUint1
	x70, x71 = fiatScMontAddcarryxU64(uint64(x46), x61, x69)
	var x72 uint64
	_, x72 = bits.Mul64(x62, 0xfffffffeffffffff)
	var x74 uint64
	var x75 uint64
	x75, x74 = bits.Mul64(x72, 0x73eda753299d7d48)
	var x76 uint64
	var x77 uint64
	x77, x76 = bits.Mul64(x72, 0x3339d80809a1d805)
	var x78 uint64
	var x79 uint64
	x79, x78 = bits.Mul64(x72, 0x53bda402fffe5bfe)
	var x80 uint64
	var x81 uint64
	x81, x80 = bits.Mul64(x72, 0xffffffff00000001)
	var x82 uint64
	var x83 fiatScMontUint1
	x82, x83 = fiatScMontAddcarryxU64(x81, x78, 0x0)
	var x84 uint64
	var x85 fiatScMontUint1
	x84, x85 = fiatScMontAddcarryxU64(x79, x76, x83)
	var x86 uint64
	var x87 fiatScMontUint1
	x86, x87 = fiatScMontAddcarryxU64(x77, x74, x85)
	x88 := (uint64(x87) + x75)
	var x90 fiatScMontUint1
	_, x90 = fiatScMontAddcarryxU64(x62, x80, 0x0)
	var x91 uint64
	var x92 fiatScMontUint1
	x91, x92 = fiatScMontAddcarryxU64(x64, x82, x90)
	var x93 uint64
	var x94 fiatScMontUint1
	x93, x94 = fiatScMontAddcarryxU64(x66, x84, x92)
	var x95 uint64
	var x96 fiatScMontUint1
	x95, x96 = fiatScMontAddcarryxU64(x68, x86, x94)
	var x97 uint64
	var x98 fiatScMontUint1
	x97, x98 = fiatScMontAddcarryxU64(x70, x88, x96)
	x99 := (uint64(x98) + uint64(x71))
	var x100 uint64
	var x101 uint64
	x101, x100 = bits.Mul64(x2, arg1[3])
	var x102 uint64
	var x103 uint64
	x103, x102 = bits.Mul64(x2, arg1[2])
	var x104 uint64
	var x105 uint64
	x105, x104 = bits.Mul64(x2, arg1[1])
	var x106 uint64
	var x107 uint64
	x107, x106 = bits.Mul64(x2, arg1[0])
	var x108 uint64
	var x109 fiatScMontUint1
	x108, x109 = fiatScMontAddcarryxU64(x107, x104, 0x0)
	var x110 uint64
	var x111 fiatScMontUint1
	x110, x111 = fiatScMontAddcarryxU64(x105, x102, x109)
	var x112 uint64
	var x113 fiatScMontUint1
	x112, x113 = fiatScMontAddcarryxU64(x103, x100, x111)
	x114 := (uint64(x113) + x101)
	var x115 uint64
	var x116 fiatScMontUint1
	x115, x116 = fiatScMontAddcarryxU64(x91, x106, 0x0)
	var x117 uint64
	var x118 fiatScMontUint1
	x117, x118 = fiatScMontAddcarryxU64(x93, x108, x116)
	var x119 uint64
	var x120 fiatScMontUint1
	x119, x120 = fiatScMontAddcarryxU64(x95, x110, x118)
	var x121 uint64
	var x122 fiatScMontUint1
	x121, x122 = fiatScMontAddcarryxU64(x97, x112, x120)
	var x123 uint64
	var x124 fiatScMontUint1
	x123, x124 = fiatScMontAddcarryxU64(x99, x114, x122)
	var x125 uint64
	_, x125 = bits.Mul64(x115, 0xfffffffeffffffff)
	var x127 uint64
	var x128 uint64
	x128, x127 = bits.Mul64(x125, 0x73eda753299d7d48)
	var x129 uint64
	var x130 uint64
	x130, x129 = bits.Mul64(x125, 0x3339d80809a1d805)
	var x131 uint64
	var x132 uint64
	x132, x131 = bits.Mul64(x125, 0x53bda402fffe5bfe)
	var x133 uint64
	var x134 uint64
	x134, x133 = bits.Mul64(x125, 0xffffffff00000001)
	var x135 uint64
	var x136 fiatScMontUint1
	x135, x136 = fiatScMontAddcarryxU64(x134, x131, 0x0)
	var x137 uint64
	var x138 fiatScMontUint1
	x137, x138 = fiatScMontAddcarryxU64(x132, x129, x136)
	var x139 uint64
	var x140 fiatScMontUint1
	x139, x140 = fiatScMontAddcarryxU64(x130, x127, x138)
	x141 := (uint64(x140) + x128)
	var x143 fiatScMontUint1
	_, x143 = fiatScMontAddcarryxU64(x115, x133, 0x0)
	var x144 uint64
	var x145 fiatScMontUint1
	x144, x145 = fiatScMontAddcarryxU64(x117, x135, x143)
	var x146 uint64
	var x147 fiatScMontUint1
	x146, x147 = fiatScMontAddcarryxU64(x119, x137, x145)
	var x148 uint64
	var x149 fiatScMontUint1
	x148, x149 = fiatScMontAddcarryxU64(x121, x139, x147)
	var x150 uint64
	var x151 fiatScMontUint1
	x150, x151 = fiatScMontAddcarryxU64(x123, x141, x149)
	x152 := (uint64(x151) + uint64(x124))
	var x153 uint64
	var x154 uint64
	x154, x153 = bits.Mul64(x3, arg1[3])
	var x155 uint64
	var x156 uint64
	x156, x155 = bits.Mul64(x3, arg1[2])
	var x157 uint64
	var x158 uint64
	x158, x157 = bits.Mul64(x3, arg1[1])
	var x159 uint64
	var x160 uint64
	x160, x159 = bits.Mul64(x3, arg1[0])
	var x161 uint64
	var x162 fiatScMontUint1
	x161, x162 = fiatScMontAddcarryxU64(x160, x157, 0x0)
	var x163 uint64
	var x164 fiatScMontUint1
	x163, x164 = fiatScMontAddcarryxU64(x158, x155, x162)
	var x165 uint64
	var x166 fiatScMontUint1
	x165, x166 = fiatScMontAddcarryxU64(x156, x153, x164)
	x167 := (uint64(x166) + x154)
	var x168 uint64
	var x169 fiatScMontUint1
	x168, x169 = fiatScMontAddcarryxU64(x144, x159, 0x0)
	var x170 uint64
	var x171 fiatScMontUint1
	x170, x171 = fiatScMontAddcarryxU64(x146, x161, x169)
	var x172 uint64
	var x173 fiatScMontUint1
	x172, x173 = fiatScMontAddcarryxU64(x148, x163, x171)
	var x174 uint64
	var x175 fiatScMontUint1
	x174, x175 = fiatScMontAddcarryxU64(x150, x165, x173)
	var x176 uint64
	var x177 fiatScMontUint1
	x176, x177 = fiatScMontAddcarryxU64(x152, x167, x175)
	var x178 uint64
	_, x178 = bits.Mul64(x168, 0xfffffffeffffffff)
	var x180 uint64
	var x181 uint64
	x181, x180 = bits.Mul64(x178, 0x73eda753299d7d48)
	var x182 uint64
	var x183 uint64
	x183, x182 = bits.Mul64(x178, 0x3339d80809a1d805)
	var x184 uint64
	var x185 uint64
	x185, x184 = bits.Mul64(x178, 0x53bda402fffe5bfe)
	var x186 uint64
	var x187 uint64
	x187, x186 = bits.Mul64(x178, 0xffffffff00000001)
	var x188 uint64
	var x189 fiatScMontUint1
	x188, x189 = fiatScMontAddcarryxU64(x187, x184, 0x0)
	var x190 uint64
	var x191 fiatScMontUint1
	x190, x191 = fiatScMontAddcarryxU64(x185, x182, x189)
	var x192 uint64
	var x193 fiatScMontUint1
	x192, x193 = fiatScMontAddcarryxU64(x183, x180, x191)
	x194 := (uint64(x193) + x181)
	var x196 fiatScMontUint1
	_, x196 = fiatScMontAddcarryxU64(x168, x186, 0x0)
	var x197 uint64
	var x198 fiatScMontUint1
	x197, x198 = fiatScMontAddcarryxU64(x170, x188, x196)
	var x199 uint64
	var x200 fiatScMontUint1
	x199, x200 = fiatScMontAddcarryxU64(x172, x190, x198)
	var x201 uint64
	var x202 fiatScMontUint1
	x201, x202 = fiatScMontAddcarryxU64(x174, x192, x200)
	var x203 uint64
	var x204 fiatScMontUint1
	x203, x204 = fiatScMontAddcarryxU64(x176, x194, x202)
	x205 := (uint64(x204) + uint64(x177))
	var x206 uint64
	var x207 fiatScMontUint1
	x206, x207 = fiatScMontSubborrowxU64(x197, 0xffffffff00000001, 0x0)
	var x208 uint64
	var x209 fiatScMontUint1
	x208, x209 = fiatScMontSubborrowxU64(x199, 0x53bda402fffe5bfe, x207)
	var x210 uint64
	var x211 fiatScMontUint1
	x210, x211 = fiatScMontSubborrowxU64(x201, 0x3339d80809a1d805, x209)
	var x212 uint64
	var x213 fiatScMontUint1
	x212, x213 = fiatScMontSubborrowxU64(x203, 0x73eda753299d7d48, x211)
	var x215 fiatScMontUint1
	_, x215 = fiatScMontSubborrowxU64(x205, uint64(0x0), x213)
	var x216 uint64
	fiatScMontCmovznzU64(&x216, x215, x206, x197)
	var x217 uint64
	fiatScMontCmovznzU64(&x217, x215, x208, x199)
	var x218 uint64
	fiatScMontCmovznzU64(&x218, x215, x210, x201)
	var x219 uint64
	fiatScMontCmovznzU64(&x219, x215, x212, x203)
	out1[0] = x216
	out1[1] = x217
	out1[2] = x218
	out1[3] = x219
}
