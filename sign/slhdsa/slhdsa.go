package slhdsa

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"io"

	"github.com/cloudflare/circl/internal/sha3"
	"github.com/cloudflare/circl/xof"
)

func KeyGen(rnd io.Reader, ins Instance) (sk *PrivateKey, pk *PublicKey, err error) {
	state, err := ins.newState()
	if err != nil {
		return nil, nil, err
	}

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
	state, err := k.Instance.newState()
	if err != nil {
		return nil, err
	}

	return k.doPureSign(state, msg, ctx, k.publicKey.seed)
}

func (k *PrivateKey) PureSign(rnd io.Reader, msg, ctx []byte) (sig []byte, err error) {
	state, err := k.Instance.newState()
	if err != nil {
		return nil, err
	}

	addRand, err := readRandom(rnd, state.n)
	if err != nil {
		return nil, err
	}

	return k.doPureSign(state, msg, ctx, addRand)
}

func (k *PrivateKey) doPureSign(s *state, msg, ctx, addRand []byte) (sig []byte, err error) {
	if len(ctx) > 255 {
		return nil, ErrContextLen
	}

	msgPrime := append(append([]byte{0, byte(len(ctx))}, ctx...), msg...)
	return s.slhSignInternal(k, msgPrime, addRand)
}

type PreHash uint

const (
	PreHashSHA256   PreHash = PreHash(crypto.SHA256)
	PreHashSHA512   PreHash = PreHash(crypto.SHA512)
	PreHashSHAKE128 PreHash = PreHash(xof.SHAKE128)
	PreHashSHAKE256 PreHash = PreHash(xof.SHAKE256)
)

func (k *PrivateKey) HashSignDeterministic(msg, ctx []byte, ph PreHash) (sig []byte, err error) {
	state, err := k.Instance.newState()
	if err != nil {
		return nil, err
	}

	return k.doHashSign(state, msg, ctx, nil, ph)
}

func (k *PrivateKey) HashSign(rnd io.Reader, msg, ctx []byte, ph PreHash) (sig []byte, err error) {
	state, err := k.Instance.newState()
	if err != nil {
		return nil, err
	}

	addRand, err := readRandom(rnd, state.n)
	if err != nil {
		return nil, err
	}

	return k.doHashSign(state, msg, ctx, addRand, ph)
}

func (k *PrivateKey) doHashSign(s *state, msg, ctx, addRand []byte, ph PreHash) (sig []byte, err error) {
	if len(ctx) > 255 {
		return nil, ErrContextLen
	}

	var phMsg []byte
	var oid10 byte
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

	msgPrime := append(append(append(append(
		[]byte{1, byte(len(ctx))}, ctx...), oid[:]...), oid10), phMsg...)
	return s.slhSignInternal(k, msgPrime, addRand)
}

func PureVerify(pub *PublicKey, msg, ctx, sig []byte) bool {
	state, err := pub.Instance.newState()
	if err != nil {
		return false
	}

	if len(ctx) > 255 {
		return false
	}

	msgPrime := append(append([]byte{0, byte(len(ctx))}, ctx...), msg...)
	return state.slhVerifyInternal(pub, msgPrime, sig)
}

func HashVerify(pub *PublicKey, msg, ctx, sig []byte, ph PreHash) bool {
	state, err := pub.Instance.newState()
	if err != nil {
		return false
	}

	if len(ctx) > 255 {
		return false
	}

	var phMsg []byte
	var oid10 byte
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
		return false
	}

	msgPrime := append(append(append(append(
		[]byte{1, byte(len(ctx))}, ctx...), oid[:]...), oid10), phMsg...)
	return state.slhVerifyInternal(pub, msgPrime, sig)
}

var oid = [10]byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02}

func readRandom(rnd io.Reader, size uint) (out []byte, err error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	out = make([]byte, size)
	_, err = io.ReadFull(rnd, out)
	return
}

var (
	ErrReading    = errors.New("sign/slhdsa: failed to read from a hash function")
	ErrWriting    = errors.New("sign/slhdsa: failed to write to a hash function")
	ErrNode       = errors.New("sign/slhdsa: invalid height or index")
	ErrMsgDigest  = errors.New("sign/slhdsa: invalid message digest bitlength")
	ErrAddRand    = errors.New("sign/slhdsa: invalid additional randomness length")
	ErrContextLen = errors.New("sign/slhdsa: context is larger than 255 bytes")
	ErrPreHash    = errors.New("sign/slhdsa: invalid prehash function")
	ErrInstance   = errors.New("sign/slhdsa: invalid SLH-DSA instance")
)
