package slhdsa

import (
	"bytes"
	"crypto"
	"crypto/subtle"

	"github.com/cloudflare/circl/internal/conv"
	"golang.org/x/crypto/cryptobyte"
)

type PrivateKey struct {
	Instance
	*privateKey
	publicKey *PublicKey
}

type privateKey struct{ seed, prfKey []byte }

func (k *PrivateKey) Marshal(b *cryptobyte.Builder) (err error) {
	b.AddBytes(k.seed)
	b.AddBytes(k.prfKey)
	b.AddValue(k.publicKey)
	return
}

func (k *PrivateKey) Unmarshal(s *cryptobyte.String) bool {
	err := k.Instance.Validate()
	if err != nil {
		return false
	}

	param := &instances[k.Instance]
	buf := make([]byte, 2*param.n)

	k.privateKey = &privateKey{
		seed:   buf[:param.n],
		prfKey: buf[param.n:],
	}
	k.publicKey = &PublicKey{Instance: k.Instance}

	return s.CopyBytes(k.seed) && s.CopyBytes(k.prfKey) && k.publicKey.Unmarshal(s)
}

func (k *PrivateKey) MarshalBinary() ([]byte, error) { return conv.MarshalBinary(k) }
func (k *PrivateKey) UnmarshalBinary(b []byte) error { return conv.UnmarshalBinary(k, b) }
func (k *PrivateKey) PublicKey() *PublicKey          { return k.publicKey }
func (k *PrivateKey) Public() crypto.PublicKey       { return k.PublicKey() }
func (k *PrivateKey) Equal(x crypto.PrivateKey) bool {
	other, ok := x.(*PrivateKey)
	return ok && k.Instance == other.Instance &&
		subtle.ConstantTimeCompare(k.seed, other.seed) == 1 &&
		subtle.ConstantTimeCompare(k.prfKey, other.prfKey) == 1 &&
		k.publicKey.Equal(other.publicKey)
}

type PublicKey struct {
	Instance
	*publicKey
}

type publicKey struct{ seed, root []byte }

func (k *PublicKey) Marshal(b *cryptobyte.Builder) (err error) {
	b.AddBytes(k.seed)
	b.AddBytes(k.root)
	return
}

func (k *PublicKey) Unmarshal(s *cryptobyte.String) bool {
	err := k.Instance.Validate()
	if err != nil {
		return false
	}

	param := &instances[k.Instance]
	buf := make([]byte, 2*param.n)

	k.publicKey = &publicKey{
		seed: buf[:param.n],
		root: buf[param.n:],
	}

	return s.CopyBytes(k.seed) && s.CopyBytes(k.root)
}

func (k *PublicKey) MarshalBinary() ([]byte, error) { return conv.MarshalBinary(k) }
func (k *PublicKey) UnmarshalBinary(b []byte) error { return conv.UnmarshalBinary(k, b) }
func (k *PublicKey) Equal(x crypto.PublicKey) bool {
	other, ok := x.(*PublicKey)
	return ok && k.Instance == other.Instance &&
		bytes.Equal(k.seed, other.seed) &&
		bytes.Equal(k.root, other.root)
}

type signature struct {
	Instance
	rnd     []byte
	forsSig forsSignature
	htSig   hyperTreeSignature
}

func (s *signature) Marshal(b *cryptobyte.Builder) (err error) {
	b.AddBytes(s.rnd)
	b.AddValue(&s.forsSig)
	b.AddValue(&s.htSig)
	return
}

func (s *signature) Unmarshal(str *cryptobyte.String) bool {
	err := s.Instance.Validate()
	if err != nil {
		return false
	}

	param := &instances[s.Instance]
	s.rnd = make([]byte, param.n)

	return str.CopyBytes(s.rnd) &&
		s.forsSig.Unmarshal(param, str) &&
		s.htSig.Unmarshal(param, str)
}
