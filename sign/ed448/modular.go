package ed448

import (
	"encoding/binary"
	"math/bits"
)

type modOrder [Size]byte

var order = modOrder{
	0xf3, 0x44, 0x58, 0xab, 0x92, 0xc2, 0x78, 0x23,
	0x55, 0x8f, 0xc5, 0x8d, 0x72, 0xc2, 0x6c, 0x21,
	0x90, 0x36, 0xd6, 0xae, 0x49, 0xdb, 0x4e, 0xc4,
	0xe9, 0x23, 0xca, 0x7c, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
	0x00,
}

var residue = []byte{
	0x34, 0xec, 0x9e, 0x52, 0xb5, 0xf5, 0x1c, 0x72,
	0xab, 0xc2, 0xe9, 0xc8, 0x35, 0xf6, 0x4c, 0x7a,
	0xbf, 0x25, 0xa7, 0x44, 0xd9, 0x92, 0xc4, 0xee,
	0x58, 0x70, 0xd7, 0x0c, 0x02,
}

// isInRange returns true if 0 <= x < order.
func (m modOrder) isInRange(x []byte) bool {
	if len(x) != Size {
		panic("wrong input size")
	}
	i := Size - 1
	for i > 0 && x[i] == m[i] {
		i--
	}
	return x[i] < m[i]
}

func toUint(b []byte) uint {
	const w = bits.UintSize / 8  // 4 or 8
	const i = bits.UintSize / 64 // 0 or 1
	_ = b[w-1]
	xLo := uint(binary.LittleEndian.Uint32(b))
	xHi := uint(binary.LittleEndian.Uint32(b[4*i:]))
	return xLo | xHi<<(32*i)
}

func byte2uint(x []byte) []uint {
	const n = bits.UintSize / 8
	lx := len(x)
	ly := (8*lx + bits.UintSize - 1) / bits.UintSize
	y := make([]uint, ly)

	for i := range y[:ly-1] {
		y[i] = toUint(x[n*i:])
	}

	for i, j := 8*(ly-1), uint(0); i < lx; i++ {
		y[ly-1] |= uint(x[i]) << (8 * j)
		j++
	}

	return y
}

func add(x, y []uint) []uint {
	l, L, zz := len(x), len(y), y
	if l > L {
		l, L, zz = L, l, x
	}
	z := make([]uint, L+1)
	c := uint(0)
	for i := 0; i < l; i++ {
		z[i], c = bits.Add(x[i], y[i], c)
	}
	for i := l; i < L; i++ {
		z[i], c = bits.Add(zz[i], 0, c)
	}
	z[L] = c
	return z
}

func mul(x, y []uint) []uint {
	z := make([]uint, len(x)+len(y))
	for i := range x {
		carry := uint(0)
		for j := range y {
			hi, lo := bits.Mul(x[i], y[j])
			lo, c := bits.Add(lo, z[i+j], 0)
			hi, _ = bits.Add(hi, 0, c)
			z[i+j], c = bits.Add(lo, carry, 0)
			carry, _ = bits.Add(hi, 0, c)
		}
		z[i+len(y)] = carry
	}
	return z
}

// reduce calculates x = x mod order of the curve.
func (m modOrder) reduce(x []byte) {
	res := byte2uint(residue)
	a := byte2uint(x)
	for i := 0; i < 3; i++ {
		a = add(mul(a[7:], res), a[0:7])
	}
}

//
// // red912 calculates x = x mod Order of the curve.
// func red912(x *[15]uint64, full bool) {
// 	// Implementation of Algs.(14.47)+(14.52) of Handbook of Applied
// 	// Cryptography, by A. Menezes, P. van Oorschot, and S. Vanstone.
// 	const ellFour0 = uint64(0x721cf5b5529eec34)
// 	const ellFour1 = uint64(0x7a4cf635c8e9c2ab)
// 	const ellFour2 = uint64(0xeec492d944a725bf)
// 	const ellFour3 = uint64(0x20cd77058)
//
// 	const ell0 = uint64(0xdc873d6d54a7bb0d)
// 	const ell1 = uint64(0xde933d8d723a70aa)
// 	const ell2 = uint64(0x3bb124b65129c96f)
// 	const ell3 = uint64(0x8335dc16)
//
// 	two848modOrder := [7]uint64{ // 2^848 mod order
// 		0xb8d79162fb442ed7,
// 		0x355e64cff8bb2502,
// 		0x23e59d7125763bf2,
// 		0xc14ba3c40e285620,
// 		0xbcb7e4d070af1a9c,
// 		0xa939f823b7292052,
// 		0x35b5529eec383402,
// 	}
// 	// fmt.Printf("x: %v\n", conv.Uint64Le2Hex(x[:]))
//
// 	var c0, c1, c2, c3, c4, c5, c6 uint64
// 	r0, r1, r2, r3 := x[0], x[1], x[2], x[3]
// 	r4, r5, r6, r7 := x[4], x[5], x[6], uint64(0)
//
// 	if full {
// 		q7 := (x[14] << 48) | (x[13] >> 16)
// 		x[14] = 0
// 		x[13] &= (uint64(1) << 16) - 1
//
// 		h0, l0 := bits.Mul64(two848modOrder[0], q7)
// 		h1, l1 := bits.Mul64(two848modOrder[1], q7)
// 		h2, l2 := bits.Mul64(two848modOrder[2], q7)
// 		h3, l3 := bits.Mul64(two848modOrder[3], q7)
// 		h4, l4 := bits.Mul64(two848modOrder[4], q7)
// 		h5, l5 := bits.Mul64(two848modOrder[5], q7)
// 		h6, l6 := bits.Mul64(two848modOrder[6], q7)
//
// 		l1, c0 = bits.Add64(h0, l1, 0)
// 		l2, c1 = bits.Add64(h1, l2, c0)
// 		l3, c2 = bits.Add64(h2, l3, c1)
// 		l4, c3 = bits.Add64(h3, l4, c2)
// 		l5, c4 = bits.Add64(h4, l5, c3)
// 		l6, c5 = bits.Add64(h5, l6, c4)
// 		l7, _ := bits.Add64(h6, 0, c5)
//
// 		//		fmt.Printf("l: %v\n", conv.Uint64Le2Hex([]uint64{l0, l1, l2, l3, l4, l5, l6, l7}))
// 		r0, c0 = bits.Add64(r0, l0, 0)
// 		r1, c1 = bits.Add64(r1, l1, c0)
// 		r2, c2 = bits.Add64(r2, l2, c1)
// 		r3, c3 = bits.Add64(r3, l3, c2)
// 		r4, c4 = bits.Add64(r4, l4, c3)
// 		r5, c5 = bits.Add64(r5, l5, c4)
// 		r6, c6 = bits.Add64(r6, l6, c5)
// 		r7, c7 := bits.Add64(r7, l7, c6)
// 		r8, c8 := bits.Add64(q0, 0, c7)
// 		r9, c9 := bits.Add64(q1, 0, c8)
// 		r10, c10 := bits.Add64(r10, 0, c9)
// 		r11, c11 := bits.Add64(r11, 0, c10)
// 		r12, c12 := bits.Add64(r12, 0, c11)
// 		r13, _ = bits.Add64(r5, l12, c12)
//
// 		//		fmt.Printf("r: %v\n", conv.Uint64Le2Hex([]uint64{r0, r1, r2, r3, r4, r5, r6}))
// 		return
//
// 		q0, q1, q2, q3 := x[7], x[8], x[9], x[10]
// 		q4, q5, q6, q7 := x[11], x[12], x[13], x[14]
// 		// fmt.Printf("r: %v\n", conv.Uint64Le2Hex([]uint64{r0, r1, r2, r3, r4, r5, r6}))
// 		// fmt.Printf("q: %v\n", conv.Uint64Le2Hex([]uint64{q0, q1, q2, q3, q4, q5, q6, q7}))
//
// 		for i := 0; i < 3; i++ {
// 			h0, s0 := bits.Mul64(q0, ellFour0)
// 			h1, s1 := bits.Mul64(q1, ellFour0)
// 			h2, s2 := bits.Mul64(q2, ellFour0)
// 			h3, s3 := bits.Mul64(q3, ellFour0)
// 			h4, s4 := bits.Mul64(q4, ellFour0)
// 			h5, s5 := bits.Mul64(q5, ellFour0)
// 			h6, s6 := bits.Mul64(q6, ellFour0)
//
// 			s1, c0 = bits.Add64(h0, s1, 0)
// 			s2, c1 = bits.Add64(h1, s2, c0)
// 			s3, c2 = bits.Add64(h2, s3, c1)
// 			s4, c3 = bits.Add64(h3, s4, c2)
// 			s5, c4 = bits.Add64(h4, s5, c3)
// 			s6, c5 = bits.Add64(h5, s6, c4)
// 			s7, _ := bits.Add64(h6, 0, c5)
//
// 			h0, l0 := bits.Mul64(q0, ellFour1)
// 			h1, l1 := bits.Mul64(q1, ellFour1)
// 			h2, l2 := bits.Mul64(q2, ellFour1)
// 			h3, l3 := bits.Mul64(q3, ellFour1)
// 			h4, l4 := bits.Mul64(q4, ellFour1)
// 			h5, l5 := bits.Mul64(q5, ellFour1)
// 			h6, l6 := bits.Mul64(q6, ellFour1)
//
// 			l1, c0 = bits.Add64(h0, l1, 0)
// 			l2, c1 = bits.Add64(h1, l2, c0)
// 			l3, c2 = bits.Add64(h2, l3, c1)
// 			l4, c3 = bits.Add64(h3, s4, c2)
// 			l5, c4 = bits.Add64(h4, s5, c3)
// 			l6, c5 = bits.Add64(h5, s6, c4)
// 			// l7, _ := bits.Add64(h6, 0, c5)
//
// 			s1, c0 = bits.Add64(s1, l0, 0)
// 			s2, c1 = bits.Add64(s2, l1, c0)
// 			s3, c2 = bits.Add64(s3, l2, c1)
// 			s4, c3 = bits.Add64(s4, l3, c2)
// 			s5, c4 = bits.Add64(s5, l4, c3)
// 			s6, c5 = bits.Add64(s6, l5, c4)
// 			s7, s8 := bits.Add64(l6, 0, c5)
//
// 			s2, c0 = bits.Add64(s2, q0, 0)
// 			s3, c1 = bits.Add64(s3, q1, c0)
// 			s4, c2 = bits.Add64(s4, q2, c1)
// 			s5, c3 = bits.Add64(s5, q3, c2)
// 			s6, c4 = bits.Add64(s6, q4, c3)
// 			s7, c5 = bits.Add64(s7, q5, c4)
// 			s8, s9 := bits.Add64(s8, 0, c5)
//
// 			// fmt.Printf("q0: %v\n", conv.Uint64Le2BigInt([]uint64{q0, q1, q2, q3, q4, q5, q6}))
// 			q := q0 | q1 | q2 | q3
// 			m := -((q | -q) >> 63) // if q=0 then m=0...0 else m=1..1
// 			s0 &= m
// 			s1 &= m
// 			s2 &= m
// 			s3 &= m
// 			q0, q1, q2, q3 = s7, s8, s9, s7
//
// 			if (i+1)%2 == 0 {
// 				r0, c0 = bits.Add64(r0, s0, 0)
// 				r1, c1 = bits.Add64(r1, s1, c0)
// 				r2, c2 = bits.Add64(r2, s2, c1)
// 				r3, c3 = bits.Add64(r3, s3, c2)
// 				r4, c4 = bits.Add64(r4, s4, c3)
// 				r5, c5 = bits.Add64(r5, s5, c4)
// 				r6, c6 = bits.Add64(r6, s6, c5)
// 				r7, _ = bits.Add64(r7, 0, c6)
// 			} else {
// 				r0, c0 = bits.Sub64(r0, s0, 0)
// 				r1, c1 = bits.Sub64(r1, s1, c0)
// 				r2, c2 = bits.Sub64(r2, s2, c1)
// 				r3, c3 = bits.Sub64(r3, s3, c2)
// 				r4, c4 = bits.Add64(r4, s4, c3)
// 				r5, c5 = bits.Add64(r5, s5, c4)
// 				r6, c6 = bits.Add64(r6, s6, c5)
// 				r7, _ = bits.Sub64(r7, 0, c6)
// 			}
// 		}
//
// 		m := -(r4 >> 63)
// 		r0, c0 = bits.Add64(r0, m&ellFour0, 0)
// 		r1, c1 = bits.Add64(r1, m&ellFour1, c0)
// 		r2, c2 = bits.Add64(r2, m&ellFour2, c1)
// 		r3, c3 = bits.Add64(r3, m&ellFour3, c2)
// 		r4, c4 = bits.Add64(r4, 0, c3)
// 		r5, c5 = bits.Add64(r5, 0, c4)
// 		r6, _ = bits.Add64(r6, m&1, c5)
// 		x[7], x[8], x[9], x[10], x[11], x[12], x[13] = 0, 0, 0, 0, 0, 0, 0
// 	}
//
// 	q0 := (r4 << 2) | (r3 >> 62)
// 	r3 &= (uint64(1) << 62) - 1
//
// 	h0, s0 := bits.Mul64(ell0, q0)
// 	h1, s1 := bits.Mul64(ell1, q0)
// 	s1, c0 = bits.Add64(h0, s1, 0)
// 	s2, _ := bits.Add64(h1, 0, c0)
//
// 	r0, c0 = bits.Sub64(r0, s0, 0)
// 	r1, c1 = bits.Sub64(r1, s1, c0)
// 	r2, c2 = bits.Sub64(r2, s2, c1)
// 	r3, _ = bits.Sub64(r3, 0, c2)
//
// 	x[0], x[1], x[2], x[3], x[4], x[5], x[6] = r0, r1, r2, r3, r4, r5, r6
// }
