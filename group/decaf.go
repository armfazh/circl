package group

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"math/bits"

	"github.com/cloudflare/circl/expander"
	"github.com/cloudflare/circl/internal/ted448"
	fp "github.com/cloudflare/circl/math/fp448"
	"github.com/cloudflare/circl/xof"
)

// Decaf Group
//
// Decaf (3) is a prime-order group constructed as a quotient of groups. A Decaf
// element can be represented by any point in the coset P+J[2], where J is a
// Jacobi quartic curve and J[2] are its 2-torsion points.
// Since P+J[2] has four points, Decaf specifies rules to choose one canonical
// representative, which has a unique encoding. Two representations are
// equivalent if they belong to the same coset.
//
// The types Elt and Scalar provide methods to perform arithmetic operations on
// the Decaf group.
//
// Version
//
// This implementation uses Decaf v1.0 of the encoding (see (4,5) for a complete
// specification).
//
// References
//
// (1) https://www.shiftleft.org/papers/goldilocks
//
// (2) https://tools.ietf.org/html/rfc7748
//
// (3) https://doi.org/10.1007/978-3-662-47989-6_34 and https://www.shiftleft.org/papers/decaf
//
// (4) https://sourceforge.net/p/ed448goldilocks/code/ci/v1.0/tree/
//
// (5) https://mailarchive.ietf.org/arch/msg/cfrg/S4YUTt_5eD4kwYbDuhEK0tXT1aM/

var Decaf448 Group = decaf448{}

type decaf448 struct{}

func (g decaf448) String() string      { return "decaf448" }
func (g decaf448) Params() *Params     { return &Params{fp.Size, fp.Size, fp.Size} }
func (g decaf448) NewElement() Element { return g.Identity() }
func (g decaf448) NewScalar() Scalar   { return new(dScl) }
func (g decaf448) Identity() Element   { return &dElt{ted448.Identity()} }
func (g decaf448) Generator() Element  { return &dElt{ted448.Generator()} }
func (g decaf448) Order() Scalar       { return &dScl{ted448.Order()} }

func (g decaf448) RandomElement(rd io.Reader) Element {
	b := make([]byte, fp.Size)
	if n, err := io.ReadFull(rd, b); err != nil || n != len(b) {
		panic(err)
	}
	return g.HashToElement(b, nil)
}
func (g decaf448) RandomScalar(rd io.Reader) Scalar {
	b := make([]byte, fp.Size)
	if n, err := io.ReadFull(rd, b); err != nil || n != len(b) {
		panic(err)
	}
	return g.HashToScalar(b, nil)
}
func (g decaf448) RandomNonZeroScalar(rd io.Reader) Scalar {
	zero := g.NewScalar()
	for {
		s := g.RandomScalar(rd)
		if !s.IsEqual(zero) {
			return s
		}
	}
}
func (g decaf448) HashToElementNonUniform(data, dst []byte) Element {
	return g.HashToElement(data, dst)
}
func (g decaf448) HashToElement(data, dst []byte) Element {
	exp := expander.NewExpanderXOF(xof.SHAKE256, 224, dst)
	uniformBytes := exp.Expand(data, 2*fp.Size)
	var p1, p2 dElt
	err := p1.UnmarshalBinary(uniformBytes[:fp.Size])
	if err != nil {
		panic(err)
	}
	err = p2.UnmarshalBinary(uniformBytes[fp.Size : 2*fp.Size])
	if err != nil {
		panic(err)
	}
	p1.p.Add(&p2.p)
	return &p1
}
func (g decaf448) HashToScalar(data, dst []byte) Scalar {
	exp := expander.NewExpanderXOF(xof.SHAKE256, 224, dst)
	uniformBytes := exp.Expand(data, 64)
	s := new(dScl)
	s.k.FromBytes(uniformBytes)
	return s
}

type dElt struct{ p ted448.Point }

func (e dElt) String() string            { return e.p.String() }
func (e *dElt) Set(a Element)            { e.p = a.(*dElt).p }
func (e *dElt) Copy() Element            { return &dElt{e.p} }
func (e *dElt) Add(a, b Element) Element { e.Set(a); e.p.Add(&b.(*dElt).p); return e }
func (e *dElt) Dbl(a Element) Element    { e.Set(a); e.p.Double(); return e }
func (e *dElt) Neg(a Element) Element    { e.Set(a); e.p.Neg(); return e }
func (e *dElt) MulGen(s Scalar) Element  { ted448.ScalarBaseMult(&e.p, &s.(*dScl).k); return e }
func (e *dElt) Mul(a Element, s Scalar) Element {
	ted448.ScalarMult(&e.p, &s.(*dScl).k, &a.(*dElt).p)
	return e
}

func (e *dElt) IsIdentity() bool {
	b0 := fp.IsZero(&e.p.X)
	b1 := 1 - fp.IsZero(&e.p.Y)
	b2 := 1 - fp.IsZero(&e.p.Z)
	return (b0 & b1 & b2) == 1
}

func (e *dElt) IsEqual(a Element) bool {
	aa := a.(*dElt)
	l, r := &fp.Elt{}, &fp.Elt{}
	fp.Mul(l, &e.p.X, &aa.p.Y)
	fp.Mul(r, &aa.p.X, &e.p.Y)
	fp.Sub(l, l, r)
	return fp.IsZero(l) == 1
}

func (e *dElt) MarshalBinaryCompress() ([]byte, error) { return e.MarshalBinary() }
func (e *dElt) MarshalBinary() ([]byte, error) {
	var encS [fp.Size]byte
	err := e.marshalBinary(encS[:])
	return encS[:], err
}

func (e *dElt) marshalBinary(enc []byte) error {
	x, ta, tb, z := &e.p.X, &e.p.Ta, &e.p.Tb, &e.p.Z
	t, t2, s := &fp.Elt{}, &fp.Elt{}, &fp.Elt{}
	one := fp.One()
	fp.Mul(t, ta, tb)             // t = ta*tb
	t0, t1 := *x, *t              // (t0,t1) = (x,t)
	fp.AddSub(&t0, &t1)           // (t0,t1) = (x+t,x-t)
	fp.Mul(&t1, &t0, &t1)         // t1 = num = (x+t)*(x-t) = x^2*(z^2-y^2)/z^2
	fp.Mul(&t0, &t1, &aMinusD)    // t0 = (a-d)*(x+t)*(x-t) = (a-d)*x^2*(z^2-y^2)/z^2
	fp.Sqr(t2, x)                 // t2 = x^2
	fp.Mul(&t0, &t0, t2)          // t0 = x^2*(a-d)*(x+t)*(x-t) = (a-d)*x^4*(z^2-y^2)/z^2
	fp.InvSqrt(&t0, &one, &t0)    // t0 = isr = z/(x^2*sqrt((a-d)*(z^2-y^2)))
	fp.Mul(&t1, &t1, &t0)         // t1 = ratio = (z^2-y^2)/(z*sqrt((a-d)*(z^2-y^2)))
	fp.Mul(t2, &t1, &sqrtAMinusD) // t2 = altx = sqrt((z^2-y^2))/z
	isNeg := fp.Parity(t2)        // isNeg = sgn(t2)
	fp.Neg(t2, &t1)               // t2 = -t1
	fp.Cmov(&t1, t2, uint(isNeg)) // if t2 is negative then t1 = -t1
	fp.Mul(s, &t1, z)             // s = t1*z
	fp.Sub(s, s, t)               // s = t1*z - t
	fp.Mul(s, s, x)               // s = x*(t1*z - t)
	fp.Mul(s, s, &t0)             // s = isr*x*(t1*z - t)
	fp.Mul(s, s, &aMinusD)        // s = (a-d)*isr*x*(t1*z - t)
	isNeg = fp.Parity(s)          // isNeg = sgn(s)
	fp.Neg(&t0, s)                // t0 = -s
	fp.Cmov(s, &t0, uint(isNeg))  // if s is negative then s = -s
	return fp.ToBytes(enc[:], s)
}

func (e *dElt) UnmarshalBinary(data []byte) error {
	if len(data) < fp.Size {
		return io.ErrShortBuffer
	}

	s := &fp.Elt{}
	copy(s[:], data[:fp.Size])
	p := fp.P()
	isLessThanP := isLessThan(s[:], p[:])
	isPositiveS := 1 - fp.Parity(s)

	den, num := &fp.Elt{}, &fp.Elt{}
	isr, altx, t0 := &fp.Elt{}, &fp.Elt{}, &fp.Elt{}
	x, y := &fp.Elt{}, &fp.Elt{}
	one := fp.One()
	paramD := ted448.ParamD()
	fp.Sqr(t0, s)                     // t0  = s^2
	fp.Sub(den, &one, t0)             // den = 1 + a*s^2
	fp.Add(y, &one, t0)               // y   = 1 - a*s^2
	fp.Mul(num, t0, &paramD)          // num = d*s^2
	fp.Add(num, num, num)             //     = 2*d*s^2
	fp.Add(num, num, num)             //     = 4*d*s^2
	fp.Sqr(t0, den)                   // t0  = den^2 = (1 + a*s^2)^2
	fp.Sub(num, t0, num)              // num = den^2 - 4*d*s^2
	fp.Mul(t0, t0, num)               // t0  = den^2*num
	isQR := fp.InvSqrt(isr, &one, t0) // isr = 1/(den*sqrt(num))
	fp.Mul(altx, isr, den)            // altx = isr*den
	fp.Mul(altx, altx, s)             //      = s*isr*den
	fp.Add(altx, altx, altx)          //      = 2*s*isr*den
	fp.Mul(altx, altx, &sqrtAMinusD)  //      = 2*s*isr*den*sqrt(A-D)
	isNegX := fp.Parity(altx)         // isNeg = sgn(altx)
	fp.Neg(t0, isr)                   // t0 = -isr
	fp.Cmov(isr, t0, uint(isNegX))    // if altx is negative then isr = -isr
	fp.Mul(t0, isr, den)              // t0 = isr*den
	fp.Mul(x, t0, isr)                // x = isr^2*den
	fp.Mul(x, x, num)                 // x = isr^2*den*num
	fp.Mul(x, x, s)                   // x = s*isr^2*den*num
	fp.Add(x, x, x)                   // x = 2*s*isr^2*den*num
	fp.Mul(y, y, t0)                  // y = (1 - a*s^2)*isr*den

	b0 := isPositiveS
	b1 := isLessThanP
	b2 := isQR
	b := uint(subtle.ConstantTimeEq(int32(4*b2+2*b1+b0), 0x7))
	fp.Cmov(&e.p.X, x, b)
	fp.Cmov(&e.p.Y, y, b)
	fp.Cmov(&e.p.Ta, x, b)
	fp.Cmov(&e.p.Tb, y, b)
	fp.Cmov(&e.p.Z, &one, b)
	if b == 0 {
		return ErrInvalidDecoding
	}
	return nil
}

type dScl struct{ k ted448.Scalar }

func (s *dScl) String() string         { return s.k.String() }
func (s *dScl) Add(a, b Scalar) Scalar { s.k.Add(&a.(*dScl).k, &b.(*dScl).k); return s }
func (s *dScl) Sub(a, b Scalar) Scalar { s.k.Sub(&a.(*dScl).k, &b.(*dScl).k); return s }
func (s *dScl) Mul(a, b Scalar) Scalar { s.k.Mul(&a.(*dScl).k, &b.(*dScl).k); return s }
func (s *dScl) Neg(a Scalar) Scalar    { s.k.Neg(&a.(*dScl).k); return s }
func (s *dScl) Inv(a Scalar) Scalar    { s.k.Inv(&a.(*dScl).k); return s }
func (s *dScl) IsEqual(a Scalar) bool {
	aa := a.(*dScl)
	aa.k.Red()
	s.k.Red()
	return subtle.ConstantTimeCompare(s.k[:], aa.k[:]) == 1
}

func (s *dScl) SetUint64(n uint64) {
	s.k = ted448.Scalar{}
	binary.LittleEndian.PutUint64(s.k[:], n)
}

func (s *dScl) MarshalBinary() ([]byte, error) {
	out := make([]byte, ted448.ScalarSize)
	s.k.Red()
	copy(out, s.k[:])
	return out, nil
}

func (s *dScl) UnmarshalBinary(data []byte) error {
	if len(data) < ted448.ScalarSize {
		return io.ErrShortBuffer
	}
	s.k.FromBytes(data[:ted448.ScalarSize])
	return nil
}

// isLessThan returns 1 if 0 <= x < y, and assumes that slices are of the
// same length and are interpreted in little-endian order.
func isLessThan(x, y []byte) int {
	i := len(x) - 1
	for i > 0 && x[i] == y[i] {
		i--
	}
	xi := int(x[i])
	yi := int(y[i])
	return ((xi - yi) >> (bits.UintSize - 1)) & 1
}

// ErrInvalidDecoding alerts of an error during decoding a point.
var ErrInvalidDecoding = errors.New("invalid decaf decoding")

var (
	// aMinusD is paramA-paramD = (-1)-(-39082) = 39081.
	aMinusD = fp.Elt{0xa9, 0x98}
	// sqrtAMinusD is the smallest root of sqrt(paramA-paramD) = sqrt(39081).
	sqrtAMinusD = fp.Elt{
		0x36, 0x27, 0x57, 0x45, 0x0f, 0xef, 0x42, 0x96,
		0x52, 0xce, 0x20, 0xaa, 0xf6, 0x7b, 0x33, 0x60,
		0xd2, 0xde, 0x6e, 0xfd, 0xf4, 0x66, 0x9a, 0x83,
		0xba, 0x14, 0x8c, 0x96, 0x80, 0xd7, 0xa2, 0x64,
		0x4b, 0xd5, 0xb8, 0xa5, 0xb8, 0xa7, 0xf1, 0xa1,
		0xa0, 0x6a, 0xa2, 0x2f, 0x72, 0x8d, 0xf6, 0x3b,
		0x68, 0xf7, 0x24, 0xeb, 0xfb, 0x62, 0xd9, 0x22,
	}
)
