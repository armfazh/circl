// Package group provides prime-order groups based on elliptic curves.
package group

import (
	"encoding"
	"errors"
	"io"
)

type Params struct {
	ElementLength           uint // Length in bytes of an element.
	CompressedElementLength uint // Length in bytes of a compressed element.
	ScalarLength            uint // Length in bytes of a scalar.
}

// Group represents a prime-order group based on elliptic curves.
type Group interface {
	Params() *Params // Params returns parameters for the group
	NewElement() Element
	NewScalar() Scalar
	Identity() Element
	Generator() Element
	Order() Scalar
	RandomElement(io.Reader) Element
	RandomScalar(io.Reader) Scalar
	NewHash(dst []byte) HashToElement
	NewHashNonUniform(dst []byte) HashToElement
	NewHashToScalar(dst []byte) HashToScalar
}

// Element represents an abstract element of a prime-order group.
type Element interface {
	IsIdentity() bool
	IsEqual(Element) bool
	Add(Element, Element) Element
	Dbl(Element) Element
	Neg(Element) Element
	Mul(Element, Scalar) Element
	MulGen(Scalar) Element
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	MarshalBinaryCompress() ([]byte, error)
}

// Scalar represents an integer scalar.
type Scalar interface {
	IsEqual(Scalar) bool
	Add(Scalar, Scalar) Scalar
	Sub(Scalar, Scalar) Scalar
	Mul(Scalar, Scalar) Scalar
	Neg(Scalar) Scalar
	Inv(Scalar) Scalar
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

type HashToElement interface {
	Reset()
	io.Writer
	Sum() Element
}

type HashToScalar interface {
	Reset()
	io.Writer
	Sum() Scalar
}

var (
	ErrType      = errors.New("type mismatch")
	ErrUnmarshal = errors.New("error unmarshaling")
)
