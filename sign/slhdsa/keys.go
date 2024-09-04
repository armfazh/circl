package slhdsa

import (
	"bytes"
	"crypto"
	"crypto/subtle"

	"github.com/cloudflare/circl/internal/conv"
	"github.com/cloudflare/circl/sign"
	"golang.org/x/crypto/cryptobyte"
)

type PrivateKey struct {
	ParamID      ParamID
	seed, prfKey []byte
	publicKey    PublicKey
}

func (p *params) PrivateKeySize() int { return 2*p.n + p.PublicKeySize() }

func (k *PrivateKey) Marshal(b *cryptobyte.Builder) error {
	b.AddBytes(k.seed)
	b.AddBytes(k.prfKey)
	b.AddValue(&k.publicKey)
	return nil
}

func (k *PrivateKey) Unmarshal(s *cryptobyte.String) bool {
	params := k.ParamID.params()
	var b []byte
	if !s.ReadBytes(&b, params.PrivateKeySize()) {
		return false
	}

	c := cursor(b)
	return k.fromBytes(params, &c)
}

func (k *PrivateKey) fromBytes(p *params, c *cursor) bool {
	k.ParamID = p.id
	k.seed = c.Next(p.n)
	k.prfKey = c.Next(p.n)
	return k.publicKey.fromBytes(p, c)
}

func (k *PrivateKey) Scheme() sign.Scheme            { return k.ParamID }
func (k *PrivateKey) MarshalBinary() ([]byte, error) { return conv.MarshalBinary(k) }
func (k *PrivateKey) UnmarshalBinary(b []byte) error { return conv.UnmarshalBinary(k, b) }
func (k *PrivateKey) PublicKey() *PublicKey          { r := k.publicKey.copy(); return &r }
func (k *PrivateKey) Public() crypto.PublicKey       { return k.PublicKey() }
func (k *PrivateKey) Equal(x crypto.PrivateKey) bool {
	other, ok := x.(*PrivateKey)
	return ok && k.ParamID == other.ParamID &&
		subtle.ConstantTimeCompare(k.seed, other.seed) == 1 &&
		subtle.ConstantTimeCompare(k.prfKey, other.prfKey) == 1 &&
		k.publicKey.Equal(&other.publicKey)
}

type PublicKey struct {
	ParamID    ParamID
	seed, root []byte
}

func (p *params) PublicKeySize() int { return 2 * p.n }

func (k *PublicKey) Marshal(b *cryptobyte.Builder) error {
	b.AddBytes(k.seed)
	b.AddBytes(k.root)
	return nil
}

func (k *PublicKey) Unmarshal(s *cryptobyte.String) bool {
	params := k.ParamID.params()
	var b []byte
	if !s.ReadBytes(&b, params.PublicKeySize()) {
		return false
	}

	c := cursor(b)
	return k.fromBytes(params, &c)
}

func (k *PublicKey) fromBytes(p *params, c *cursor) bool {
	k.ParamID = p.id
	k.seed = c.Next(p.n)
	k.root = c.Next(p.n)
	return len(*c) == 0
}

func (k *PublicKey) copy() (out PublicKey) {
	params := k.ParamID.params()
	c := cursor(make([]byte, params.PublicKeySize()))
	out.fromBytes(params, &c)
	copy(out.seed, k.seed)
	copy(out.root, k.root)
	return
}

func (k *PublicKey) Scheme() sign.Scheme            { return k.ParamID }
func (k *PublicKey) MarshalBinary() ([]byte, error) { return conv.MarshalBinary(k) }
func (k *PublicKey) UnmarshalBinary(b []byte) error { return conv.UnmarshalBinary(k, b) }
func (k *PublicKey) Equal(x crypto.PublicKey) bool {
	other, ok := x.(*PublicKey)
	return ok && k.ParamID == other.ParamID &&
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
