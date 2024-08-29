// Package slhdsa provides Stateless Hash-based Digital Signature Algorithm.
//
// This package is compliant with FIPS 205.
//
// FIPS-205: https://doi.org/10.6028/NIST.FIPS.205
package slhdsa

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"io"

	"github.com/cloudflare/circl/internal/sha3"
)

const MaxContextSize = 255

func KeyGen(rnd io.Reader, ins Instance) (sk *PrivateKey, pk *PublicKey, err error) {
	state, err := ins.newState()
	if err != nil {
		return nil, nil, err
	}
	defer state.clear()

	skSeed, err := readRandom(rnd, state.n)
	if err != nil {
		return nil, nil, err
	}

	skPrf, err := readRandom(rnd, state.n)
	if err != nil {
		return nil, nil, err
	}

	pkSeed, err := readRandom(rnd, state.n)
	if err != nil {
		return nil, nil, err
	}

	sk, pk = state.slhKeyGenInternal(skSeed, skPrf, pkSeed)

	return
}

func (k *PrivateKey) PureSignDeterministic(msg, ctx []byte) (sig []byte, err error) {
	return k.doPureSign(msg, ctx, k.publicKey.seed)
}

func (k *PrivateKey) PureSign(rnd io.Reader, msg, ctx []byte) (sig []byte, err error) {
	err = k.Instance.Validate()
	if err != nil {
		return nil, err
	}

	addRand, err := readRandom(rnd, instances[k.Instance].n)
	if err != nil {
		return nil, err
	}

	return k.doPureSign(msg, ctx, addRand)
}

func (k *PrivateKey) doPureSign(msg, ctx, addRand []byte) (sig []byte, err error) {
	msgPrime, err := getMsg(msg, ctx)
	if err != nil {
		return nil, err
	}

	state, err := k.Instance.newState()
	if err != nil {
		return nil, err
	}
	defer state.clear()

	return state.slhSignInternal(k, msgPrime, addRand)
}

func PureVerify(pub *PublicKey, msg, ctx, sig []byte) (ok bool) {
	msgPrime, err := getMsg(msg, ctx)
	if err != nil {
		return false
	}

	state, err := pub.Instance.newState()
	if err != nil {
		return false
	}
	defer state.clear()

	return state.slhVerifyInternal(pub, msgPrime, sig)
}

func getMsg(msg, ctx []byte) (msgPrime []byte, err error) {
	if len(ctx) > MaxContextSize {
		return nil, ErrContext
	}

	return append(append([]byte{0, byte(len(ctx))}, ctx...), msg...), nil
}

func (k *PrivateKey) HashSignDeterministic(msg, ctx []byte, ph PreHashID) (sig []byte, err error) {
	return k.doHashSign(msg, ctx, k.publicKey.seed, ph)
}

func (k *PrivateKey) HashSign(rnd io.Reader, msg, ctx []byte, ph PreHashID) (sig []byte, err error) {
	err = k.Instance.Validate()
	if err != nil {
		return nil, err
	}

	addRand, err := readRandom(rnd, instances[k.Instance].n)
	if err != nil {
		return nil, err
	}

	return k.doHashSign(msg, ctx, addRand, ph)
}

func (k *PrivateKey) doHashSign(msg, ctx, addRand []byte, ph PreHashID) (sig []byte, err error) {
	msgPrime, err := getPrehashedMsg(msg, ctx, ph)
	if err != nil {
		return nil, err
	}

	state, err := k.Instance.newState()
	if err != nil {
		return nil, err
	}
	defer state.clear()

	return state.slhSignInternal(k, msgPrime, addRand)
}

func HashVerify(pub *PublicKey, msg, ctx, sig []byte, ph PreHashID) (ok bool) {
	msgPrime, err := getPrehashedMsg(msg, ctx, ph)
	if err != nil {
		return false
	}

	state, err := pub.Instance.newState()
	if err != nil {
		return false
	}
	defer state.clear()

	return state.slhVerifyInternal(pub, msgPrime, sig)
}

func getPrehashedMsg(msg, ctx []byte, ph PreHashID) (msgPrime []byte, err error) {
	if len(ctx) > MaxContextSize {
		return nil, ErrContext
	}

	var oid10 byte
	var phMsg []byte
	switch ph {
	case PreHashSHA256:
		oid10 = 0x01
		sum := sha256.Sum256(msg)
		phMsg = sum[:]
	case PreHashSHA512:
		oid10 = 0x03
		sum := sha512.Sum512(msg)
		phMsg = sum[:]
	case PreHashSHAKE128:
		oid10 = 0x0B
		phMsg = make([]byte, 256/8)
		sha3.ShakeSum128(phMsg, msg)
	case PreHashSHAKE256:
		oid10 = 0x0C
		phMsg = make([]byte, 512/8)
		sha3.ShakeSum256(phMsg, msg)
	default:
		return nil, ErrPreHash
	}

	oid := [10]byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02}

	return append(append(append(append(
		[]byte{1, byte(len(ctx))}, ctx...), oid[:]...), oid10), phMsg...), nil
}

func readRandom(rnd io.Reader, size int) (out []byte, err error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	out = make([]byte, size)
	_, err = io.ReadFull(rnd, out)
	return
}

var (
	ErrReading   = errors.New("sign/slhdsa: failed to read from a hash function")
	ErrWriting   = errors.New("sign/slhdsa: failed to write to a hash function")
	ErrNode      = errors.New("sign/slhdsa: invalid height or index")
	ErrMsgDigest = errors.New("sign/slhdsa: invalid message digest bitlength")
	ErrAddRand   = errors.New("sign/slhdsa: invalid additional randomness length")
	ErrContext   = errors.New("sign/slhdsa: context is larger than MaxContextSize bytes")
	ErrPreHash   = errors.New("sign/slhdsa: invalid prehash function")
	ErrInstance  = errors.New("sign/slhdsa: invalid SLH-DSA instance")
	ErrSigParse  = errors.New("sign/slhdsa: error parsing signature")
)
