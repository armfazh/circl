package ed448

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"errors"
	"io"
	"math/big"

	"github.com/cloudflare/circl/internal/conv"
	"golang.org/x/crypto/sha3"
)

// Size is the length in bytes of Ed448 keys.
const Size = 57

// PublicKey represents a public key of Ed25519.
type PublicKey []byte

// PrivateKey represents a private key of Ed25519.
type PrivateKey []byte

// KeyPair implements crypto.Signer (golang.org/pkg/crypto/#Signer) interface.
type KeyPair struct{ private, public [Size]byte }

// GetPrivate returns a copy of the private key.
func (k *KeyPair) GetPrivate() PrivateKey { return makeCopy(&k.private) }

// GetPublic returns the public key corresponding to the private key.
func (k *KeyPair) GetPublic() PublicKey { return makeCopy(&k.public) }

// Public returns a crypto.PublicKey corresponding to the private key.
func (k *KeyPair) Public() crypto.PublicKey { return k.GetPublic() }

// Sign signs the given message with priv.
// Ed448 performs two passes over messages to be signed and therefore cannot
// handle pre-hashed messages. Thus opts.HashFunc() must return zero to
// indicate the message hasn't been hashed. This can be achieved by passing
// crypto.Hash(0) as the value for opts.
func (k *KeyPair) Sign(rand io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.Hash(0) {
		return nil, errors.New("ed448: cannot sign hashed message")
	}
	return Sign(k, message), nil
}

// GenerateKey generates a public/private key pair using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func GenerateKey(rnd io.Reader) (*KeyPair, error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	private := make(PrivateKey, Size)
	if _, err := io.ReadFull(rnd, private); err != nil {
		return nil, err
	}
	return NewKeyFromSeed(private), nil
}

// NewKeyFromSeed generates a pair of Ed25519 signing keys given a
// previously-generated private key.
func NewKeyFromSeed(private PrivateKey) *KeyPair {
	if l := len(private); l != Size {
		panic("ed448: bad private key length")
	}
	pk := new(KeyPair)
	var k [2 * Size]byte
	sha3.ShakeSum256(k[:], private[:])
	clamp(k[:])
	reduceModOrder(k[:Size])
	div4(k[:Size])
	var P pointR1
	P.fixedMult(k[:Size])
	P.ToBytes(pk.public[:])
	copy(pk.private[:], private[:Size])
	return pk
}

// Sign returns the signature of a message using both the private and public
// keys of the signer.
func Sign(k *KeyPair, message []byte) []byte {
	var h, r, hRAM [2 * Size]byte
	sha3.ShakeSum256(h[:], k.private[:])
	clamp(h[:])
	H := sha3.NewShake256()
	_, _ = H.Write(h[Size:])
	_, _ = H.Write(message)
	_, _ = H.Read(r[:])
	reduceModOrder(r[:])
	div4(r[:Size])

	var P pointR1
	P.fixedMult(r[:Size])
	signature := make([]byte, 2*Size)
	P.ToBytes(signature[:Size])

	H.Reset()
	_, _ = H.Write(signature[:Size])
	_, _ = H.Write(k.public[:])
	_, _ = H.Write(message)
	_, _ = H.Read(hRAM[:])
	reduceModOrder(hRAM[:])
	calculateS(signature[Size:], r[:Size], hRAM[:Size], h[:Size])
	return signature
}

// Verify returns true if the signature is valid. Failure cases are invalid
// signature, or when the public key cannot be decoded.
func Verify(public PublicKey, message, sig []byte) bool {
	if l := len(public); l != Size {
		panic("ed448: bad public key length")
	}
	if isLtOrder := isLessThan(sig[Size:], curve.order[:Size]); !isLtOrder {
		return false
	}
	var hRAM [2 * Size]byte
	var P pointR1
	if ok := P.FromBytes(public[:]); !ok {
		return false
	}
	H := sha3.NewShake256()
	_, _ = H.Write(sig[:Size])
	_, _ = H.Write(public[:])
	_, _ = H.Write(message)
	_, _ = H.Read(hRAM[:])
	reduceModOrder(hRAM[:])
	if ok := verifyRange(sig[Size:]); !ok {
		return false
	}
	var Q pointR1
	P.neg()
	Q.doubleMult(&P, sig[Size:], hRAM[:Size])
	var enc [Size]byte
	Q.ToBytes(enc[:])
	return bytes.Equal(enc[:], sig[:Size])
}

func clamp(k []byte) {
	k[0] &= 252
	k[Size-2] |= 0x80
	k[Size-1] = 0x00
}

func makeCopy(in *[Size]byte) []byte {
	out := make([]byte, Size)
	copy(out, in[:])
	return out
}

func div4(k []byte) {
	four := big.NewInt(4)
	kk := conv.BytesLe2BigInt(k)
	order := conv.BytesLe2BigInt(curve.order[:])
	four.ModInverse(four, order)
	kk.Mul(kk, four).Mod(kk, order)
	conv.BigInt2BytesLe(k, kk)
}

// reduceModOrder calculates k = k mod order of the curve.
func reduceModOrder(k []byte) {
	kk := conv.BytesLe2BigInt(k)
	order := conv.BytesLe2BigInt(curve.order[:])
	kk.Mod(kk, order)
	conv.BigInt2BytesLe(k, kk)
	/*	if len(k) == Size || len(k) == 2*Size {
			var X [15]uint64
			numWords := len(k) >> 3
			for i := 0; i < numWords; i++ {
				X[i] = binary.LittleEndian.Uint64(k[i*8 : (i+1)*8])
			}
			X[numWords] = uint64(k[112]) | (uint64(k[113]) << 8)
			//red912(&X, len(k) == 2*Size)
			for i := 0; i < numWords; i++ {
				binary.LittleEndian.PutUint64(k[i*8:(i+1)*8], X[i])
			}
			k[112] = 0
			k[113] = 0
		} else {
			panic("wrong size")
		}
	*/
}

// red912 calculates x = x mod Order of the curve.
func red912(x *[15]uint64, full bool) {}

/*	// Implementation of Algs.(14.47)+(14.52) of Handbook of Applied
	// Cryptography, by A. Menezes, P. van Oorschot, and S. Vanstone.
	const ellFour0 = uint64(0x721cf5b5529eec34)
	const ellFour1 = uint64(0x7a4cf635c8e9c2ab)
	const ellFour2 = uint64(0xeec492d944a725bf)
	const ellFour3 = uint64(0x20cd77058)

	const ell0 = uint64(0xdc873d6d54a7bb0d)
	const ell1 = uint64(0xde933d8d723a70aa)
	const ell2 = uint64(0x3bb124b65129c96f)
	const ell3 = uint64(0x8335dc16)

	two848modOrder := [7]uint64{ // 2^848 mod order
		0xb8d79162fb442ed7,
		0x355e64cff8bb2502,
		0x23e59d7125763bf2,
		0xc14ba3c40e285620,
		0xbcb7e4d070af1a9c,
		0xa939f823b7292052,
		0x35b5529eec383402,
	}
	// fmt.Printf("x: %v\n", conv.Uint64Le2Hex(x[:]))

	var c0, c1, c2, c3, c4, c5, c6 uint64
	r0, r1, r2, r3 := x[0], x[1], x[2], x[3]
	r4, r5, r6, r7 := x[4], x[5], x[6], uint64(0)

	if full {
		q7 := (x[14] << 48) | (x[13] >> 16)
		x[14] = 0
		x[13] &= (uint64(1) << 16) - 1

		h0, l0 := bits.Mul64(two848modOrder[0], q7)
		h1, l1 := bits.Mul64(two848modOrder[1], q7)
		h2, l2 := bits.Mul64(two848modOrder[2], q7)
		h3, l3 := bits.Mul64(two848modOrder[3], q7)
		h4, l4 := bits.Mul64(two848modOrder[4], q7)
		h5, l5 := bits.Mul64(two848modOrder[5], q7)
		h6, l6 := bits.Mul64(two848modOrder[6], q7)

		l1, c0 = bits.Add64(h0, l1, 0)
		l2, c1 = bits.Add64(h1, l2, c0)
		l3, c2 = bits.Add64(h2, l3, c1)
		l4, c3 = bits.Add64(h3, l4, c2)
		l5, c4 = bits.Add64(h4, l5, c3)
		l6, c5 = bits.Add64(h5, l6, c4)
		l7, _ := bits.Add64(h6, 0, c5)

//		fmt.Printf("l: %v\n", conv.Uint64Le2Hex([]uint64{l0, l1, l2, l3, l4, l5, l6, l7}))
		r0, c0 = bits.Add64(r0, l0, 0)
		r1, c1 = bits.Add64(r1, l1, c0)
		r2, c2 = bits.Add64(r2, l2, c1)
		r3, c3 = bits.Add64(r3, l3, c2)
		r4, c4 = bits.Add64(r4, l4, c3)
		r5, c5 = bits.Add64(r5, l5, c4)
		r6, c6 = bits.Add64(r6, l6, c5)
		r7, c7 := bits.Add64(r7, l7, c6)
		r8, c8 := bits.Add64(q0, 0, c7)
		r9, c9 := bits.Add64(q1, 0, c8)
		r10, c10 := bits.Add64(r10, 0, c9)
		r11, c11 := bits.Add64(r11, 0, c10)
		r12, c12 := bits.Add64(r12, 0, c11)
		r13, _ = bits.Add64(r5, l12, c12)

//		fmt.Printf("r: %v\n", conv.Uint64Le2Hex([]uint64{r0, r1, r2, r3, r4, r5, r6}))
		return

		q0, q1, q2, q3 := x[7], x[8], x[9], x[10]
		q4, q5, q6, q7 := x[11], x[12], x[13], x[14]
		// fmt.Printf("r: %v\n", conv.Uint64Le2Hex([]uint64{r0, r1, r2, r3, r4, r5, r6}))
		// fmt.Printf("q: %v\n", conv.Uint64Le2Hex([]uint64{q0, q1, q2, q3, q4, q5, q6, q7}))

		for i := 0; i < 3; i++ {
			h0, s0 := bits.Mul64(q0, ellFour0)
			h1, s1 := bits.Mul64(q1, ellFour0)
			h2, s2 := bits.Mul64(q2, ellFour0)
			h3, s3 := bits.Mul64(q3, ellFour0)
			h4, s4 := bits.Mul64(q4, ellFour0)
			h5, s5 := bits.Mul64(q5, ellFour0)
			h6, s6 := bits.Mul64(q6, ellFour0)

			s1, c0 = bits.Add64(h0, s1, 0)
			s2, c1 = bits.Add64(h1, s2, c0)
			s3, c2 = bits.Add64(h2, s3, c1)
			s4, c3 = bits.Add64(h3, s4, c2)
			s5, c4 = bits.Add64(h4, s5, c3)
			s6, c5 = bits.Add64(h5, s6, c4)
			s7, _ := bits.Add64(h6, 0, c5)

			h0, l0 := bits.Mul64(q0, ellFour1)
			h1, l1 := bits.Mul64(q1, ellFour1)
			h2, l2 := bits.Mul64(q2, ellFour1)
			h3, l3 := bits.Mul64(q3, ellFour1)
			h4, l4 := bits.Mul64(q4, ellFour1)
			h5, l5 := bits.Mul64(q5, ellFour1)
			h6, l6 := bits.Mul64(q6, ellFour1)

			l1, c0 = bits.Add64(h0, l1, 0)
			l2, c1 = bits.Add64(h1, l2, c0)
			l3, c2 = bits.Add64(h2, l3, c1)
			l4, c3 = bits.Add64(h3, s4, c2)
			l5, c4 = bits.Add64(h4, s5, c3)
			l6, c5 = bits.Add64(h5, s6, c4)
			// l7, _ := bits.Add64(h6, 0, c5)

			s1, c0 = bits.Add64(s1, l0, 0)
			s2, c1 = bits.Add64(s2, l1, c0)
			s3, c2 = bits.Add64(s3, l2, c1)
			s4, c3 = bits.Add64(s4, l3, c2)
			s5, c4 = bits.Add64(s5, l4, c3)
			s6, c5 = bits.Add64(s6, l5, c4)
			s7, s8 := bits.Add64(l6, 0, c5)

			s2, c0 = bits.Add64(s2, q0, 0)
			s3, c1 = bits.Add64(s3, q1, c0)
			s4, c2 = bits.Add64(s4, q2, c1)
			s5, c3 = bits.Add64(s5, q3, c2)
			s6, c4 = bits.Add64(s6, q4, c3)
			s7, c5 = bits.Add64(s7, q5, c4)
			s8, s9 := bits.Add64(s8, 0, c5)

			// fmt.Printf("q0: %v\n", conv.Uint64Le2BigInt([]uint64{q0, q1, q2, q3, q4, q5, q6}))
			q := q0 | q1 | q2 | q3
			m := -((q | -q) >> 63) // if q=0 then m=0...0 else m=1..1
			s0 &= m
			s1 &= m
			s2 &= m
			s3 &= m
			q0, q1, q2, q3 = s7, s8, s9, s7

			if (i+1)%2 == 0 {
				r0, c0 = bits.Add64(r0, s0, 0)
				r1, c1 = bits.Add64(r1, s1, c0)
				r2, c2 = bits.Add64(r2, s2, c1)
				r3, c3 = bits.Add64(r3, s3, c2)
				r4, c4 = bits.Add64(r4, s4, c3)
				r5, c5 = bits.Add64(r5, s5, c4)
				r6, c6 = bits.Add64(r6, s6, c5)
				r7, _ = bits.Add64(r7, 0, c6)
			} else {
				r0, c0 = bits.Sub64(r0, s0, 0)
				r1, c1 = bits.Sub64(r1, s1, c0)
				r2, c2 = bits.Sub64(r2, s2, c1)
				r3, c3 = bits.Sub64(r3, s3, c2)
				r4, c4 = bits.Add64(r4, s4, c3)
				r5, c5 = bits.Add64(r5, s5, c4)
				r6, c6 = bits.Add64(r6, s6, c5)
				r7, _ = bits.Sub64(r7, 0, c6)
			}
		}

		m := -(r4 >> 63)
		r0, c0 = bits.Add64(r0, m&ellFour0, 0)
		r1, c1 = bits.Add64(r1, m&ellFour1, c0)
		r2, c2 = bits.Add64(r2, m&ellFour2, c1)
		r3, c3 = bits.Add64(r3, m&ellFour3, c2)
		r4, c4 = bits.Add64(r4, 0, c3)
		r5, c5 = bits.Add64(r5, 0, c4)
		r6, _ = bits.Add64(r6, m&1, c5)
		x[7], x[8], x[9], x[10], x[11], x[12], x[13] = 0, 0, 0, 0, 0, 0, 0
	}

	q0 := (r4 << 2) | (r3 >> 62)
	r3 &= (uint64(1) << 62) - 1

	h0, s0 := bits.Mul64(ell0, q0)
	h1, s1 := bits.Mul64(ell1, q0)
	s1, c0 = bits.Add64(h0, s1, 0)
	s2, _ := bits.Add64(h1, 0, c0)

	r0, c0 = bits.Sub64(r0, s0, 0)
	r1, c1 = bits.Sub64(r1, s1, c0)
	r2, c2 = bits.Sub64(r2, s2, c1)
	r3, _ = bits.Sub64(r3, 0, c2)

	x[0], x[1], x[2], x[3], x[4], x[5], x[6] = r0, r1, r2, r3, r4, r5, r6
}
*/
// calculateS performs s = r+k*a mod Order of the curve
func calculateS(s, r, k, a []byte) {
	rr := conv.BytesLe2BigInt(r)
	kk := conv.BytesLe2BigInt(k)
	aa := conv.BytesLe2BigInt(a)
	order := conv.BytesLe2BigInt(curve.order[:])
	ss := kk.Mul(kk, aa).Add(kk, rr).Mod(kk, order)
	conv.BigInt2BytesLe(s, ss)
	/*
		K := [7]uint64{
			binary.LittleEndian.Uint64(k[0*8 : 1*8]),
			binary.LittleEndian.Uint64(k[1*8 : 2*8]),
			binary.LittleEndian.Uint64(k[2*8 : 3*8]),
			binary.LittleEndian.Uint64(k[3*8 : 4*8]),
		}
		S := [15]uint64{
			binary.LittleEndian.Uint64(r[0*8 : 1*8]),
			binary.LittleEndian.Uint64(r[1*8 : 2*8]),
			binary.LittleEndian.Uint64(r[2*8 : 3*8]),
			binary.LittleEndian.Uint64(r[3*8 : 4*8]),
		}
		var c3 uint64
		for i := range K {
			ai := binary.LittleEndian.Uint64(a[i*8 : (i+1)*8])

			h0, l0 := bits.Mul64(K[0], ai)
			h1, l1 := bits.Mul64(K[1], ai)
			h2, l2 := bits.Mul64(K[2], ai)
			h3, l3 := bits.Mul64(K[3], ai)

			l1, c0 := bits.Add64(h0, l1, 0)
			l2, c1 := bits.Add64(h1, l2, c0)
			l3, c2 := bits.Add64(h2, l3, c1)
			l4, _ := bits.Add64(h3, 0, c2)

			S[i+0], c0 = bits.Add64(S[i+0], l0, 0)
			S[i+1], c1 = bits.Add64(S[i+1], l1, c0)
			S[i+2], c2 = bits.Add64(S[i+2], l2, c1)
			S[i+3], c3 = bits.Add64(S[i+3], l3, c2)
			S[i+4], _ = bits.Add64(S[i+4], l4, c3)
		}
		red912(&S, true)
		binary.LittleEndian.PutUint64(s[0*8:1*8], S[0])
		binary.LittleEndian.PutUint64(s[1*8:2*8], S[1])
		binary.LittleEndian.PutUint64(s[2*8:3*8], S[2])
		binary.LittleEndian.PutUint64(s[3*8:4*8], S[3])
	*/
}

// verifyRange returns true if 0 <= x < Order.
func verifyRange(x []byte) bool {
	order := [Size]byte{
		0xf3, 0x44, 0x58, 0xab, 0x92, 0xc2, 0x78, 0x23, 0x55, 0x8f, 0xc5,
		0x8d, 0x72, 0xc2, 0x6c, 0x21, 0x90, 0x36, 0xd6, 0xae, 0x49, 0xdb,
		0x4e, 0xc4, 0xe9, 0x23, 0xca, 0x7c, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x3f,
	}
	i := Size - 1
	for i > 0 && x[i] == order[i] {
		i--
	}
	return x[i] < order[i]
}

// isLessThan returns true if 0 <= x < y, both slices must have the same length.
func isLessThan(x, y []byte) bool {
	i := Size - 1
	for i > 0 && x[i] == y[i] {
		i--
	}
	return x[i] < y[i]
}
