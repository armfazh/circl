package hpke

import (
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha256" // linking sha256 packages.
	_ "crypto/sha512" // linking sha512 packages.
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"

	"github.com/cloudflare/circl/kem"
)

type shortKem struct {
	kemBase
	elliptic.Curve
}

func (s shortKem) PrivateKeySize() int        { return s.byteSize() }
func (s shortKem) SeedSize() int              { return s.byteSize() }
func (s shortKem) CiphertextSize() int        { return 1 + 2*s.byteSize() }
func (s shortKem) PublicKeySize() int         { return 1 + 2*s.byteSize() }
func (s shortKem) EncapsulationSeedSize() int { return s.byteSize() }

func (s shortKem) byteSize() int { return (s.Params().BitSize + 7) / 8 }

func (s shortKem) sizeDH() int { return s.byteSize() }
func (s shortKem) calcDH(dh []byte, sk kem.PrivateKey, pk kem.PublicKey) error {
	PK, ok := pk.(*shortPubKey)
	if !ok {
		return kem.ErrTypeMismatch
	}
	SK, ok := sk.(*shortPrivKey)
	if !ok {
		return kem.ErrTypeMismatch
	}
	l := len(dh)
	x, _ := s.ScalarMult(PK.x, PK.y, SK.k) // only x-coordinate is used.
	b := x.Bytes()
	copy(dh[l-len(b):l], b)
	return nil
}
func (s shortKem) DeriveKey(seed []byte) (kem.PublicKey, kem.PrivateKey) {
	// Implementation based on https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-06.html#name-derivekeypair
	if len(seed) != s.SeedSize() {
		panic(kem.ErrSeedSize)
	}

	var bitmask = byte(0xFF)
	if s.Params().BitSize == 521 {
		bitmask = 0x01
	}

	dkpPrk := s.labeledExtract(nil, []byte("dkp_prk"), seed)
	var bytes []byte
	ctr := 0
	for skBig := new(big.Int); skBig.Sign() == 0 || skBig.Cmp(s.Params().N) >= 0; ctr++ {
		if ctr > 255 {
			panic("derive key error")
		}
		bytes = s.labeledExpand(
			dkpPrk,
			[]byte("candidate"),
			[]byte{byte(ctr)},
			uint16(s.byteSize()),
		)
		bytes[0] &= bitmask
		skBig.SetBytes(bytes)
	}
	l := s.PrivateKeySize()
	sk := &shortPrivKey{s, make([]byte, l), nil}
	copy(sk.k[l-len(bytes):], bytes)
	return sk.Public(), sk
}
func (s shortKem) GenerateKey() (kem.PublicKey, kem.PrivateKey, error) {
	sk, x, y, err := elliptic.GenerateKey(s, rand.Reader)
	pub := &shortPubKey{s, x, y}
	return pub, &shortPrivKey{s, sk, pub}, err
}

func (s shortKem) UnmarshalBinaryPrivateKey(
	data []byte,
) (kem.PrivateKey, error) {
	l := s.PrivateKeySize()
	if len(data) < l {
		return nil, errors.New("invalid private key")
	}
	sk := &shortPrivKey{s, make([]byte, l), nil}
	copy(sk.k[l-len(data):l], data[:l])
	return sk, nil
}
func (s shortKem) UnmarshalBinaryPublicKey(data []byte) (kem.PublicKey, error) {
	x, y := elliptic.Unmarshal(s, data)
	if x == nil {
		return nil, errors.New("invalid public key")
	}
	return &shortPubKey{s, x, y}, nil
}

type shortPubKey struct {
	c    shortKem
	x, y *big.Int
}

func (k *shortPubKey) String() string     { return fmt.Sprintf("x: %v\ny: %v", k.x.Text(16), k.y.Text(16)) }
func (k *shortPubKey) Scheme() kem.Scheme { return k.c }
func (k *shortPubKey) MarshalBinary() ([]byte, error) {
	return elliptic.Marshal(k.c, k.x, k.y), nil
}
func (k *shortPubKey) Equal(pk kem.PublicKey) bool {
	k1, ok := pk.(*shortPubKey)
	return ok &&
		k.c.Params().Name == k1.c.Params().Name &&
		k.x.Cmp(k1.x) == 0 &&
		k.y.Cmp(k1.y) == 0
}

type shortPrivKey struct {
	c   shortKem
	k   []byte
	pub *shortPubKey
}

func (k *shortPrivKey) String() string     { return fmt.Sprintf("%x", k.k) }
func (k *shortPrivKey) Scheme() kem.Scheme { return k.c }
func (k *shortPrivKey) MarshalBinary() ([]byte, error) {
	return append(make([]byte, 0, k.c.PrivateKeySize()), k.k...), nil
}
func (k *shortPrivKey) Equal(pk kem.PrivateKey) bool {
	k1, ok := pk.(*shortPrivKey)
	return ok &&
		k.c.Params().Name == k1.c.Params().Name &&
		subtle.ConstantTimeCompare(k.k, k1.k) == 1
}
func (k *shortPrivKey) Public() kem.PublicKey {
	if k.pub == nil {
		x, y := k.c.ScalarBaseMult(k.k)
		k.pub = &shortPubKey{k.c, x, y}
	}
	return k.pub
}
