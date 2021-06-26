package group

import (
	"io"
	"math/big"
)

// func NewHashToField(
// 	p *big.Int,
// 	L uint,
// ) HasherToField {
// 	return hashToField{p, L}
// }
//
// type hashToField struct {
// 	p *big.Int
// 	L uint
// }
//
// func (h hashToField) Reset() {}
// func (h hashToField) Sum(n uint) []*big.Int {
// 	out := make([]*big.Int, n)
// 	return out
// }
// func (h hashToField) Write(p []byte) (n int, err error) {
// 	return 0, nil
// }

// HashToField generates a set of elements {u1,..., uN} = Hash(b) where each
// u in GF(p) and L is the security parameter.
func HashToField(u []big.Int, in []byte, rw io.ReadWriter, p *big.Int, _L uint) {
	_, _ = rw.Write(in)
	bytes, _ := io.ReadAll(rw)
	L := len(bytes) / len(u)
	for i := range u {
		j := i * L
		u[i].Mod(u[i].SetBytes(bytes[j:j+L]), p)
	}
}

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

type HasherToField interface {
	io.Writer
	Sum(n uint) []*big.Int
	Reset()
}
