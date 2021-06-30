package group

import (
	"io"
)

type HasherToElement interface {
	io.Writer
	Sum() Element
	Reset()
}

type HasherToScalar interface {
	io.Writer
	Sum() Scalar
	Reset()
}
