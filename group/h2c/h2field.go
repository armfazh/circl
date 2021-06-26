package h2c

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
func (fp FieldParams) NewHash(hFunc crypto.Hash, dst []byte) h2f {
	return h2f{fp, NewExpanderMD(hFunc, dst)}
}

// HashToFieldXOF returns a HashToField function based on an extendable output function.
func (fp FieldParams) NewHashFromXOF(xFunc xof.ID, dst []byte) h2f {
	return h2f{fp, NewExpanderXOF(xFunc, fp.KSecLevel, dst)}
}

// h2f implements HashToField interface.
type h2f struct {
	FieldParams
	Expander
}

func (h h2f) Sum(u []*big.Int) {
	// L = ceil((ceil(log2(p)) + k) / 8), where k is the security parameter.
	L := (h.P.BitLen() + int(h.KSecLevel) + 7) / 8
	bytes := make([]byte, len(u)*L)
	h.Expand(bytes)
	for i := range u {
		j := i * L
		u[i].Mod(u[i].SetBytes(bytes[j:j+L]), h.P)
	}
}
