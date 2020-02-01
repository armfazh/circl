package ed448

import (
	"encoding/binary"
	"fmt"

	fp "github.com/cloudflare/circl/math/fp448"
)

type pointR1 struct{ x, y, z, ta, tb fp.Elt }
type pointR2 struct {
	pointR3
	z2 fp.Elt
}
type pointR3 struct{ addYX, subYX, dt2 fp.Elt }

func (P pointR1) String() string {
	return fmt.Sprintf("\nx=  %v\ny=  %v\nta= %v\ntb= %v\nz=  %v",
		P.x, P.y, P.ta, P.tb, P.z)
}
func (P pointR3) String() string {
	return fmt.Sprintf("\naddYX= %v\nsubYX= %v\ndt2=  %v",
		P.addYX, P.subYX, P.dt2)
}
func (P pointR2) String() string {
	return fmt.Sprintf("%v\nz2=  %v", &P.pointR3, P.z2)
}

func (P *pointR1) neg() {
	fp.Neg(&P.x, &P.x)
	fp.Neg(&P.ta, &P.ta)
}

func (P *pointR1) SetIdentity() {
	P.x = fp.Elt{}
	fp.SetOne(&P.y)
	fp.SetOne(&P.z)
	P.ta = fp.Elt{}
	P.tb = fp.Elt{}
}

func (P *pointR1) toAffine() {
	fp.Inv(&P.z, &P.z)
	fp.Mul(&P.x, &P.x, &P.z)
	fp.Mul(&P.y, &P.y, &P.z)
	fp.Modp(&P.x)
	fp.Modp(&P.y)
	fp.SetOne(&P.z)
	P.ta = P.x
	P.tb = P.y
}

func (P *pointR1) ToBytes(k []byte) {
	P.toAffine()
	var x [fp.Size]byte
	fp.ToBytes(k[:fp.Size], &P.y)
	fp.ToBytes(x[:], &P.x)
	b := x[0] & 1
	k[Size-1] = k[Size-1] | (b << 7)
}

func isGreaterThanP(x *fp.Elt) bool {
	const n = 8
	p := fp.P()
	x0 := binary.LittleEndian.Uint64(x[0*n : 1*n])
	x1 := binary.LittleEndian.Uint64(x[1*n : 2*n])
	x2 := binary.LittleEndian.Uint64(x[2*n : 3*n])
	x3 := binary.LittleEndian.Uint64(x[3*n : 4*n])
	x4 := binary.LittleEndian.Uint64(x[4*n : 5*n])
	x5 := binary.LittleEndian.Uint64(x[5*n : 6*n])
	x6 := binary.LittleEndian.Uint64(x[6*n : 7*n])

	p0 := binary.LittleEndian.Uint64(p[0*n : 1*n])
	p1 := binary.LittleEndian.Uint64(p[1*n : 2*n])
	p2 := binary.LittleEndian.Uint64(p[2*n : 3*n])
	p3 := binary.LittleEndian.Uint64(p[3*n : 4*n])
	p4 := binary.LittleEndian.Uint64(p[4*n : 5*n])
	p5 := binary.LittleEndian.Uint64(p[5*n : 6*n])
	p6 := binary.LittleEndian.Uint64(p[6*n : 7*n])

	if x6 >= p6 {
		return true
	} else if x5 >= p5 {
		return true
	} else if x4 >= p4 {
		return true
	} else if x3 >= p3 {
		return true
	} else if x2 >= p2 {
		return true
	} else if x1 >= p1 {
		return true
	} else if x0 >= p0 {
		return true
	}
	return false
}

func (P *pointR1) FromBytes(k []byte) bool {
	if len(k) != Size {
		panic("wrong size")
	}
	signX := k[Size-1] >> 7
	copy(P.y[:], k[:fp.Size])
	if isGreaterThanP(&P.y) {
		return false
	}
	paramDGoldilocks := paramD
	paramDGoldilocks[0] = 0x56

	one, u, v := &fp.Elt{}, &fp.Elt{}, &fp.Elt{}
	fp.SetOne(one)
	fp.Sqr(u, &P.y)                 // u = y^2
	fp.Mul(v, u, &paramDGoldilocks) // v = dy^2
	fp.Sub(u, u, one)               // u = y^2-1
	fp.Sub(v, v, one)               // v = dy^2-1
	ok := fp.InvSqrt(&P.x, u, v)    // x = sqrt(u/v)
	if !ok {
		return false
	}
	fp.Modp(&P.x) // x = x mod p
	if fp.IsZero(&P.x) && signX == 1 {
		return false
	}
	if signX != (P.x[0] & 1) {
		fp.Neg(&P.x, &P.x)
	}
	P.ta = P.x
	P.tb = P.y
	fp.SetOne(&P.z)
	return true
}

// double calculates 2P for curves with A=-1
func (P *pointR1) double() {
	Px, Py, Pz, Pta, Ptb := &P.x, &P.y, &P.z, &P.ta, &P.tb
	a, b, c, e, f, g, h := Px, Py, Pz, Pta, Px, Py, Ptb
	fp.Add(e, Px, Py) // x+y
	fp.Sqr(a, Px)     // A = x^2
	fp.Sqr(b, Py)     // B = y^2
	fp.Sqr(c, Pz)     // z^2
	fp.Add(c, c, c)   // C = 2*z^2
	fp.Add(h, a, b)   // H = A+B
	fp.Sqr(e, e)      // (x+y)^2
	fp.Sub(e, e, h)   // E = (x+y)^2-A-B
	fp.Sub(g, b, a)   // G = B-A
	fp.Sub(f, c, g)   // F = C-G
	fp.Mul(Pz, f, g)  // Z = F * G
	fp.Mul(Px, e, f)  // X = E * F
	fp.Mul(Py, g, h)  // Y = G * H, T = E * H
}

func (P *pointR1) mixAdd(Q *pointR3) {
	fp.Add(&P.z, &P.z, &P.z) // D = 2*z1
	P.coreAddition(Q)
}

func (P *pointR1) add(Q *pointR2) {
	fp.Mul(&P.z, &P.z, &Q.z2) // D = 2*z1*z2
	P.coreAddition(&Q.pointR3)
}

// coreAddition calculates P=P+Q for curves with A=-1
func (P *pointR1) coreAddition(Q *pointR3) {
	Px, Py, Pz, Pta, Ptb := &P.x, &P.y, &P.z, &P.ta, &P.tb
	addYX2, subYX2, dt2 := &Q.addYX, &Q.subYX, &Q.dt2
	a, b, c, d, e, f, g, h := Px, Py, &fp.Elt{}, Pz, Pta, Px, Py, Ptb
	fp.Mul(c, Pta, Ptb)  // t1 = ta*tb
	fp.Sub(h, Py, Px)    // y1-x1
	fp.Add(b, Py, Px)    // y1+x1
	fp.Mul(a, h, subYX2) // A = (y1-x1)*(y2-x2)
	fp.Mul(b, b, addYX2) // B = (y1+x1)*(y2+x2)
	fp.Mul(c, c, dt2)    // C = 2*D*t1*t2
	fp.Sub(e, b, a)      // E = B-A
	fp.Add(h, b, a)      // H = B+A
	fp.Sub(f, d, c)      // F = D-C
	fp.Add(g, d, c)      // G = D+C
	fp.Mul(Pz, f, g)     // Z = F * G
	fp.Mul(Px, e, f)     // X = E * F
	fp.Mul(Py, g, h)     // Y = G * H, T = E * H
}

func (P *pointR1) oddMultiples(T []pointR2) {
	var R pointR2
	n := len(T)
	T[0].fromR1(P)
	_2P := *P
	_2P.double()
	R.fromR1(&_2P)
	for i := 1; i < n; i++ {
		P.add(&R)
		T[i].fromR1(P)
	}
}

func (P *pointR1) isEqual(Q *pointR1) bool {
	l, r := &fp.Elt{}, &fp.Elt{}
	fp.Mul(l, &P.x, &Q.z)
	fp.Mul(r, &Q.x, &P.z)
	fp.Sub(l, l, r)
	b := fp.IsZero(l)
	fp.Mul(l, &P.y, &Q.z)
	fp.Mul(r, &Q.y, &P.z)
	fp.Sub(l, l, r)
	b = b && fp.IsZero(l)
	fp.Mul(l, &P.ta, &P.tb)
	fp.Mul(l, l, &Q.z)
	fp.Mul(r, &Q.ta, &Q.tb)
	fp.Mul(r, r, &P.z)
	fp.Sub(l, l, r)
	b = b && fp.IsZero(l)
	return b
}

func (P *pointR3) neg() {
	P.addYX, P.subYX = P.subYX, P.addYX
	fp.Neg(&P.dt2, &P.dt2)
}

func (P *pointR2) fromR1(Q *pointR1) {
	fp.Add(&P.addYX, &Q.y, &Q.x)
	fp.Sub(&P.subYX, &Q.y, &Q.x)
	fp.Mul(&P.dt2, &Q.ta, &Q.tb)
	fp.Mul(&P.dt2, &P.dt2, &paramD)
	fp.Add(&P.dt2, &P.dt2, &P.dt2)
	fp.Add(&P.z2, &Q.z, &Q.z)
}

func (P *pointR3) cneg(b int) {
	t := &fp.Elt{}
	fp.Cswap(&P.addYX, &P.subYX, uint(b))
	fp.Neg(t, &P.dt2)
	fp.Cmov(&P.dt2, t, uint(b))
}

func (P *pointR3) cmov(Q *pointR3, b int) {
	fp.Cmov(&P.addYX, &Q.addYX, uint(b))
	fp.Cmov(&P.subYX, &Q.subYX, uint(b))
	fp.Cmov(&P.dt2, &Q.dt2, uint(b))
}
