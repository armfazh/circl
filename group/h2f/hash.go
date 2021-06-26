// Package h2f provides methods for hashing to field elements.
package h2f

import (
	"crypto"
	"io"
	"math/big"

	"github.com/cloudflare/circl/xof"
)

type HashToField interface {
	// Reset cleans the internal state to allow writing another input. Discards
	// any input written previously.
	Reset()
	// Use writer to consume the input of the expander. Panics if it is invoked
	// after Sum function was called.
	io.Writer
	// Sum sets an initialized slice of big.Int with field elements such
	// that 0 <= b[i] < p.
	Sum(b []*big.Int)
}

type FieldParams struct {
	P         *big.Int
	KSecLevel uint
}

// HashToFieldMD returns a HashToField function based on a hash function.
func (fp FieldParams) NewHash(hFunc crypto.Hash, dst []byte) hashToField {
	return hashToField{fp, NewExpanderMD(hFunc, dst)}
}

// HashToFieldXOF returns a HashToField function based on an extendable output function.
func (fp FieldParams) NewHashFromXOF(xFunc xof.ID, dst []byte) hashToField {
	return hashToField{fp, NewExpanderXOF(xFunc, fp.KSecLevel, dst)}
}

// hashToField implements the HashToField interface.
type hashToField struct {
	FieldParams
	Expander
}

func (h hashToField) Sum(u []*big.Int) {
	// L = ceil((ceil(log2(p)) + k) / 8), where k is the security parameter.
	L := (h.P.BitLen() + int(h.KSecLevel) + 7) / 8
	bytes := make([]byte, len(u)*L)
	h.Expand(bytes)
	for i := range u {
		j := i * L
		u[i].Mod(u[i].SetBytes(bytes[j:j+L]), h.P)
	}
}
