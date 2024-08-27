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

func (p *params) PrivateKeySize() int { return 2*p.n + p.PublicKeySize() }

func (k *PrivateKey) Marshal(b *cryptobyte.Builder) error {
	b.AddBytes(k.seed)
	b.AddBytes(k.prfKey)
	b.AddValue(k.publicKey)
	return nil
}

func (k *PrivateKey) Unmarshal(s *cryptobyte.String) bool {
	p, err := k.Instance.getParams()
	if err != nil {
		return false
	}

	var b []byte
	if !s.ReadBytes(&b, p.PrivateKeySize()) {
		return false
	}

	c := cursor(b)
	k.privateKey = &privateKey{
		seed:   c.Next(p.n),
		prfKey: c.Next(p.n),
	}
	k.publicKey = &PublicKey{
		Instance: k.Instance,
		publicKey: &publicKey{
			seed: c.Next(p.n),
			root: c.Next(p.n),
		},
	}

	return true
}

func (k *PrivateKey) MarshalBinary() ([]byte, error) { return conv.MarshalBinary(k) }
func (k *PrivateKey) UnmarshalBinary(b []byte) error { return conv.UnmarshalBinary(k, b) }
func (k *PrivateKey) PublicKey() *PublicKey          { return k.publicKey.copy() }
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

func (p *params) PublicKeySize() int { return 2 * p.n }

func (k *PublicKey) Marshal(b *cryptobyte.Builder) error {
	b.AddBytes(k.seed)
	b.AddBytes(k.root)
	return nil
}

func (k *PublicKey) Unmarshal(s *cryptobyte.String) bool {
	p, err := k.Instance.getParams()
	if err != nil {
		return false
	}

	var b []byte
	if !s.ReadBytes(&b, p.PublicKeySize()) {
		return false
	}

	k.publicKey = &publicKey{
		seed: b[:p.n],
		root: b[p.n:],
	}

	return true
}

func (k *PublicKey) copy() *PublicKey {
	p, err := k.Instance.getParams()
	if err != nil {
		return nil
	}

	buf := make([]byte, p.PublicKeySize())
	pk := &PublicKey{
		Instance: k.Instance,
		publicKey: &publicKey{
			seed: buf[:p.n],
			root: buf[p.n:],
		},
	}
	copy(pk.seed, k.publicKey.seed)
	copy(pk.root, k.publicKey.root)

	return pk
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
	rnd     []byte             // n bytes
	forsSig forsSignature      // forsSigSize() bytes
	htSig   hyperTreeSignature // hyperTreeSigSize() bytes
}

func (p *params) SignatureSize() int { return p.n + p.forsSigSize() + p.hyperTreeSigSize() }

func (s *signature) fromBytes(p *params, c *cursor) bool {
	s.rnd = c.Next(p.n)
	s.forsSig.fromBytes(p, c)
	s.htSig.fromBytes(p, c)
	return len(*c) == 0
}
