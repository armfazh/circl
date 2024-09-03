package slhdsa

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"io"

	"github.com/cloudflare/circl/internal/sha3"
	"github.com/cloudflare/circl/sign"
)

var _ sign.Scheme = Instance(0)
var _ sign.PrivateKey = &PrivateKey{}
var _ sign.PublicKey = &PublicKey{}

func (k *PublicKey) Scheme() sign.Scheme  { return k.Instance }
func (k *PrivateKey) Scheme() sign.Scheme { return k.Instance }

type SignatureOpts struct {
	PreHashId       PreHashID
	Context         []byte
	IsDeterministic bool
}

func (s SignatureOpts) HashFunc() (h crypto.Hash) {
	switch s.PreHashId {
	case PreHashSHA256, PreHashSHA512:
		h = crypto.Hash(s.PreHashId)
	}
	return
}

func (k *PrivateKey) Sign(rnd io.Reader, message []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	var phFunc PreHashID = NoPreHash
	var context []byte = []byte{}
	var isDeterministic = false

	if opts != nil {
		switch opts.HashFunc() {
		case crypto.SHA256:
			phFunc = PreHashSHA256
		case crypto.SHA512:
			phFunc = PreHashSHA512
		}

		signOptions, ok := (interface{})(opts).(*sign.SignatureOpts)
		if ok {
			context = []byte(signOptions.Context)
		}

		myOptions, ok := (interface{})(opts).(*SignatureOpts)
		if ok {
			phFunc = myOptions.PreHashId
			context = myOptions.Context
			isDeterministic = myOptions.IsDeterministic
		}
	}

	var msg Message
	if phFunc == NoPreHash {
		msg = NewMessage(message)
	} else {
		msg, err = NewMessageWithPreHash(phFunc)
		if err != nil {
			return nil, err
		}

		_, err = msg.Write(message)
		if err != nil {
			return nil, err
		}
	}

	if isDeterministic {
		signature, err = k.SignDeterministic(&msg, context)
	} else {
		signature, err = k.SignRandomized(rand.Reader, &msg, context)
	}

	return
}

// Name of the scheme.
func (i Instance) Name() string { return i.String() }

// GenerateKey creates a new key-pair.
func (i Instance) GenerateKey() (sign.PublicKey, sign.PrivateKey, error) {
	return GenerateKey(rand.Reader, i)
}

// Creates a signature using the PrivateKey on the given message and
// returns the signature. opts are additional options which can be nil.
//
// Panics if key is nil or wrong type or opts context is not supported.
func (i Instance) Sign(sk sign.PrivateKey, message []byte, opts *sign.SignatureOpts) (signature []byte) {
	k, ok := sk.(*PrivateKey)
	if !ok || i != k.Instance {
		panic(sign.ErrTypeMismatch)
	}

	var context []byte
	if opts != nil {
		context = []byte(opts.Context)
	}

	var m Message
	_, err := m.Write(message)
	if err != nil {
		return nil
	}

	signature, err = k.SignRandomized(rand.Reader, &m, context)
	if err != nil {
		return nil
	}

	return signature
}

// Checks whether the given signature is a valid signature set by
// the private key corresponding to the given public key on the
// given message. opts are additional options which can be nil.
//
// Panics if key is nil or wrong type or opts context is not supported.
func (i Instance) Verify(pk sign.PublicKey, message []byte, signature []byte, opts *sign.SignatureOpts) bool {
	k, ok := pk.(*PublicKey)
	if !ok || i != k.Instance {
		panic(sign.ErrTypeMismatch)
	}

	var context []byte
	if opts != nil {
		context = []byte(opts.Context)
	}

	var m Message
	_, err := m.Write(message)
	if err != nil {
		return false
	}

	return Verify(k, &m, context, signature)
}

// Deterministically derives a keypair from a seed. If you're unsure,
// you're better off using GenerateKey().
//
// Panics if seed is not of length SeedSize().
func (i Instance) DeriveKey(seed []byte) (sign.PublicKey, sign.PrivateKey) {
	if len(seed) != i.SeedSize() {
		panic(sign.ErrSeedSize)
	}

	p, err := i.getParams()
	if err != nil {
		panic(ErrInstance)
	}

	var rw hasher
	if p.isSha2 {
		if p.n == 16 {
			rw = &sha2rw{Hash: sha256.New()}
		} else {
			rw = &sha2rw{Hash: sha512.New()}
		}
	} else {
		rw = &sha3rw{State: sha3.NewShake256()}
	}

	_, _ = rw.Write(seed[:])
	// todo
	pub, priv, err := GenerateKey(rand.Reader, i)
	if err != nil {
		return nil, nil
	}

	return pub, priv
}

// Unmarshals a PublicKey from the provided buffer.
func (i Instance) UnmarshalBinaryPublicKey(b []byte) (sign.PublicKey, error) {
	err := i.Validate()
	if err != nil {
		return nil, err
	}

	k := &PublicKey{Instance: i}
	err = k.UnmarshalBinary(b)
	if err != nil {
		return nil, err
	}

	return k, nil
}

// Unmarshals a PublicKey from the provided buffer.
func (i Instance) UnmarshalBinaryPrivateKey(b []byte) (sign.PrivateKey, error) {
	err := i.Validate()
	if err != nil {
		return nil, err
	}

	k := &PrivateKey{Instance: i}
	err = k.UnmarshalBinary(b)
	if err != nil {
		return nil, err
	}

	return k, nil
}

// Size of binary marshalled public keys.
func (i Instance) PublicKeySize() int {
	p, err := i.getParams()
	if err != nil {
		panic(ErrInstance)
	}
	return p.PublicKeySize()
}

// Size of binary marshalled public keys.
func (i Instance) PrivateKeySize() int {
	p, err := i.getParams()
	if err != nil {
		panic(ErrInstance)
	}
	return p.PrivateKeySize()
}

// Size of signatures.
func (i Instance) SignatureSize() int {
	p, err := i.getParams()
	if err != nil {
		panic(ErrInstance)
	}
	return p.SignatureSize()
}

// Size of seeds.
func (i Instance) SeedSize() int { return i.PrivateKeySize() }

// Returns whether contexts are supported.
func (i Instance) SupportsContext() bool { return true }
