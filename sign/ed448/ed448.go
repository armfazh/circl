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
	return Sign(k, message, nil), nil
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
	if len(private) != Size {
		panic("ed448: bad private key length")
	}
	var h [2 * Size]byte
	sha3.ShakeSum256(h[:], private[:])
	clamp(h[:Size])
	reduceModOrder(h[:Size])
	div4(h[:Size])
	var P pointR1
	P.fixedMult(h[:Size])
	deg4isogeny{}.Pull(&P)
	pk := new(KeyPair)
	P.ToBytes(pk.public[:])
	copy(pk.private[:], private[:Size])
	return pk
}

// Sign returns the signature of a message using both the private and public
// keys of the signer.
func Sign(k *KeyPair, message, context []byte) []byte {
	if len(context) > 255 {
		panic("context should be at most 255 octets")
	}
	var r, h, hRAM [2 * Size]byte
	H := sha3.NewShake256()
	_, _ = H.Write(k.private[:])
	_, _ = H.Read(h[:])
	clamp(h[:Size])

	prefix := [10]byte{'S', 'i', 'g', 'E', 'd', '4', '4', '8', byte(0), byte(len(context))}
	H.Reset()
	_, _ = H.Write(prefix[:])
	_, _ = H.Write(context)
	_, _ = H.Write(h[Size:])
	_, _ = H.Write(message)
	_, _ = H.Read(r[:])
	reduceModOrder(r[:])
	rDiv4 := r
	div4(rDiv4[:Size])

	var P pointR1
	P.fixedMult(rDiv4[:Size])

	deg4isogeny{}.Pull(&P)
	signature := make([]byte, 2*Size)
	P.ToBytes(signature[:Size])

	H.Reset()
	_, _ = H.Write(prefix[:])
	_, _ = H.Write(context)
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
func Verify(public PublicKey, message, context, signature []byte) bool {
	if len(public) != Size ||
		len(signature) != 2*Size ||
		!order.isInRange(signature[Size:]) ||
		len(context) > 255 {
		return false
	}
	var P pointR1
	if ok := P.FromBytes(public); !ok {
		return false
	}
	P.neg()
	deg4isogeny{}.Push(&P)

	var hRAM [2 * Size]byte
	prefix := [10]byte{'S', 'i', 'g', 'E', 'd', '4', '4', '8', byte(0), byte(len(context))}
	H := sha3.NewShake256()
	_, _ = H.Write(prefix[:])
	_, _ = H.Write(context)
	_, _ = H.Write(signature[:Size])
	_, _ = H.Write(public[:Size])
	_, _ = H.Write(message)
	_, _ = H.Read(hRAM[:])
	reduceModOrder(hRAM[:])

	signatureDiv4 := make([]byte, 2*Size)
	hRAMDiv4 := make([]byte, 2*Size)
	copy(signatureDiv4, signature[:])
	copy(hRAMDiv4, hRAM[:])
	div4(signatureDiv4[Size:])
	div4(hRAMDiv4[:Size])

	var Q pointR1
	Q.doubleMult(&P, signatureDiv4[Size:], hRAMDiv4[:Size])
	deg4isogeny{}.Pull(&Q)

	var enc [Size]byte
	Q.ToBytes(enc[:])
	return bytes.Equal(enc[:], signature[:Size])
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
	order := conv.BytesLe2BigInt(order[:])
	four.ModInverse(four, order)
	kk.Mul(kk, four).Mod(kk, order)
	conv.BigInt2BytesLe(k, kk)
}

// reduceModOrder calculates k = k mod order of the curve.
func reduceModOrder(k []byte) {
	kk := conv.BytesLe2BigInt(k)
	order := conv.BytesLe2BigInt(order[:])
	kk.Mod(kk, order)
	conv.BigInt2BytesLe(k, kk)
}

// calculateS performs s = r+k*a mod Order of the curve
func calculateS(s, r, k, a []byte) {
	rr := conv.BytesLe2BigInt(r)
	kk := conv.BytesLe2BigInt(k)
	aa := conv.BytesLe2BigInt(a)
	order := conv.BytesLe2BigInt(order[:])
	kk.Mul(kk, aa)
	kk.Add(kk, rr)
	kk.Mod(kk, order)
	conv.BigInt2BytesLe(s, kk)
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
