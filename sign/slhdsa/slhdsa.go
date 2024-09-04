// Package slhdsa provides Stateless Hash-based Digital Signature Algorithm.
//
// This package is compliant with [FIPS 205] and supports the following
// parameter sets:
//   - SLH-DSA-SHA2-128s
//   - SLH-DSA-SHAKE-128s
//   - SLH-DSA-SHA2-128f
//   - SLH-DSA-SHAKE-128f
//   - SLH-DSA-SHA2-192s
//   - SLH-DSA-SHAKE-192s
//   - SLH-DSA-SHA2-192f
//   - SLH-DSA-SHAKE-192f
//   - SLH-DSA-SHA2-256s
//   - SLH-DSA-SHAKE-256s
//   - SLH-DSA-SHA2-256f
//   - SLH-DSA-SHAKE-256f
//
// A [ParamID] is used to identify these sets.
//
// [FIPS 205]: https://doi.org/10.6028/NIST.FIPS.205
package slhdsa

import (
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/internal/sha3"
	"github.com/cloudflare/circl/sign"
)

// GenerateKey returns a pair of keys using the parameter set specified.
// It returns an error if it fails reading from the random source.
func GenerateKey(random io.Reader, id ParamID) (pub PublicKey, priv PrivateKey, err error) {
	params := id.params()

	var skPrf, skSeed, pkSeed []byte
	skSeed, err = readRandom(random, params.n)
	if err != nil {
		return
	}

	skPrf, err = readRandom(random, params.n)
	if err != nil {
		return
	}

	pkSeed, err = readRandom(random, params.n)
	if err != nil {
		return
	}

	pub, priv = slhKeyGenInternal(params, skSeed, skPrf, pkSeed)

	return
}

// GenerateKey is similar to [GenerateKey] function, except it always reads
// random bytes from [rand.Reader].
func (id ParamID) GenerateKey() (sign.PublicKey, sign.PrivateKey, error) {
	pub, priv, err := GenerateKey(rand.Reader, id)
	if err != nil {
		return nil, nil, err
	}
	return &pub, &priv, nil
}

// Deterministically derives a pair of keys from a seed. If you're unsure,
// you're better off using [GenerateKey] function.
//
// Panics if seed is not of length [ParamID.SeedSize].
func (id ParamID) DeriveKey(seed []byte) (sign.PublicKey, sign.PrivateKey) {
	if len(seed) != id.SeedSize() {
		panic(sign.ErrSeedSize)
	}

	params := id.params()
	m := make([]byte, 3*params.n)

	if params.isSha2 {
		params.mgf1(m, seed)
	} else {
		h := sha3.NewShake256()
		_, _ = h.Write(seed[:])
		_, _ = h.Read(m)
	}

	c := cursor(m)
	skSeed := c.Next(params.n)
	skPrf := c.Next(params.n)
	pkSeed := c.Next(params.n)

	pub, priv := slhKeyGenInternal(params, skSeed, skPrf, pkSeed)

	return &pub, &priv
}

// SignRandomized returns a random signature of the message with the
// specified context.
// It returns an error if it fails reading from the random source.
func (k *PrivateKey) SignRandomized(
	rand io.Reader, message *Message, context []byte,
) (signature []byte, err error) {
	params := k.ParamID.params()

	addRand, err := readRandom(rand, params.n)
	if err != nil {
		return nil, err
	}

	return k.doSign(message, context, addRand)
}

// SignDeterministic returns the signature of the message with the
// specified context.
// It returns an error if it fails reading from the random source.
func (k *PrivateKey) SignDeterministic(
	message *Message, context []byte,
) (signature []byte, err error) {
	return k.doSign(message, context, k.publicKey.seed)
}

func (k *PrivateKey) doSign(
	message *Message, context, addRand []byte,
) (signature []byte, err error) {
	params := k.ParamID.params()

	msgPrime, err := message.getMsgPrime(context)
	if err != nil {
		return nil, err
	}

	return slhSignInternal(params, k, msgPrime, addRand)
}

// [PrivateKey.Sign] returns a signature of the message with the specified
// options.
//
// When opts is a [SignatureOpts] struct, the signature is generated as
// specified by the options. Otherwise, opts.HashFunc is used as the
// pre-hash function (allowing only SHA256 or SHA512).
// If opts is nil, the message is not prehased, and a randomized signature
// with an empty context is generated.
// It returns an error if it fails reading from the random source.
func (k *PrivateKey) Sign(
	random io.Reader, message []byte, opts crypto.SignerOpts,
) (signature []byte, err error) {
	var options SignatureOpts

	if opts != nil {
		switch opts.HashFunc() {
		case crypto.SHA256:
			options.PreHashID = PreHashSHA256
		case crypto.SHA512:
			options.PreHashID = PreHashSHA512
		}

		otherOptions, ok := opts.(SignatureOpts)
		if ok {
			options = otherOptions
		}
	}

	msg := new(Message)
	err = msg.init(options.PreHashID, message)
	if err != nil {
		return nil, err
	}

	if options.IsDeterministic {
		return k.SignDeterministic(msg, options.Context)
	} else {
		return k.SignRandomized(random, msg, options.Context)
	}
}

// [ParamID.Sign] returns a randomized signature of the message with the
// specified options.
// This function never pre-hashes the message is never prehased and uses
// the context passed in opts. If opts is nil, an empty context is used.
// It returns an empty slice if it fails reading from the random source.
//
// Panics if the key is not a [*PrivateKey] or mismatches with the ParamID.
func (id ParamID) Sign(
	key sign.PrivateKey, message []byte, opts *sign.SignatureOpts,
) (signature []byte) {
	k, ok := key.(*PrivateKey)
	if !ok || id != k.ParamID {
		panic(sign.ErrTypeMismatch)
	}

	var context []byte
	if opts != nil {
		context = []byte(opts.Context)
	}

	msg := NewMessage(message)
	signature, err := k.SignRandomized(rand.Reader, &msg, context)
	if err != nil {
		return nil
	}

	return
}

func Verify(pub *PublicKey, message *Message, context, signature []byte) bool {
	params := pub.ParamID.params()

	msgPrime, err := message.getMsgPrime(context)
	if err != nil {
		return false
	}

	return slhVerifyInternal(params, pub, msgPrime, signature)
}

// Checks whether the given signature is a valid signature set by
// the private key corresponding to the given public key on the
// given message. opts are additional options which can be nil.
//
// Panics if key is nil or wrong type or opts context is not supported.
func (id ParamID) Verify(pk sign.PublicKey, message, signature []byte, opts *sign.SignatureOpts) bool {
	k, ok := pk.(*PublicKey)
	if !ok || id != k.ParamID {
		panic(sign.ErrTypeMismatch)
	}

	var context []byte
	if opts != nil {
		context = []byte(opts.Context)
	}

	msg := NewMessage(message)

	return Verify(k, &msg, context, signature)
}

type SignatureOpts struct {
	PreHashID       PreHashID
	Context         []byte
	IsDeterministic bool
}

func (s SignatureOpts) HashFunc() (h crypto.Hash) {
	switch s.PreHashID {
	case PreHashSHA256, PreHashSHA512:
		h = crypto.Hash(s.PreHashID)
	}
	return
}

func readRandom(rnd io.Reader, size int) (out []byte, err error) {
	out = make([]byte, size)
	if rnd == nil {
		rnd = rand.Reader
	}
	_, err = io.ReadFull(rnd, out)
	return
}

var (
	ErrContext  = fmt.Errorf("sign/slhdsa: context must not be larger than MaxContextSize=%v bytes", MaxContextSize)
	ErrParam    = errors.New("sign/slhdsa: invalid SLH-DSA parameter")
	ErrPreHash  = errors.New("sign/slhdsa: invalid prehash function")
	ErrSigParse = errors.New("sign/slhdsa: failed to decode the signature")
	ErrTree     = errors.New("sign/slhdsa: invalid tree height or tree index")
	ErrWriting  = errors.New("sign/slhdsa: failed to write to a hash function")
)
