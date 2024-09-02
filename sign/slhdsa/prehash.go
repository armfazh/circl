package slhdsa

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"io"

	"github.com/cloudflare/circl/internal/sha3"
	"github.com/cloudflare/circl/xof"
)

type PreHashID byte

const (
	NoPreHash       PreHashID = PreHashID(0)
	PreHashSHA256   PreHashID = PreHashID(crypto.SHA256)
	PreHashSHA512   PreHashID = PreHashID(crypto.SHA512)
	PreHashSHAKE128 PreHashID = PreHashID(xof.SHAKE128)
	PreHashSHAKE256 PreHashID = PreHashID(xof.SHAKE256)
)

type Message struct {
	buffer bytes.Buffer
	hasher
	isPreHash bool
	oid10     byte
	outLen    int
}

func (m *Message) Write(p []byte) (n int, err error) {
	if m.isPreHash {
		return m.hasher.Write(p)
	} else {
		return m.buffer.Write(p)
	}
}

func NewPreHashedMessage(ph PreHashID) (m Message, err error) {
	switch ph {
	case PreHashSHA256:
		m.isPreHash = true
		m.oid10 = 0x01
		m.outLen = crypto.SHA256.Size()
		m.hasher = &sha2rw{Hash: sha256.New()}
	case PreHashSHA512:
		m.isPreHash = true
		m.oid10 = 0x03
		m.outLen = crypto.SHA512.Size()
		m.hasher = &sha2rw{Hash: sha512.New()}
	case PreHashSHAKE128:
		m.isPreHash = true
		m.oid10 = 0x0B
		m.outLen = 256 / 8
		m.hasher = &sha3rw{State: sha3.NewShake128()}
	case PreHashSHAKE256:
		m.isPreHash = true
		m.oid10 = 0x0C
		m.outLen = 512 / 8
		m.hasher = &sha3rw{State: sha3.NewShake256()}
	case NoPreHash:
		/* does nothing zero value stands for NoPreHash */
		break
	default:
		err = ErrPreHash
	}

	return
}

func getMsgPrime(msg *Message, context []byte) (msgPrime []byte, err error) {
	if len(context) > MaxContextSize {
		return nil, ErrContext
	}

	msgPrime = append([]byte{0, byte(len(context))}, context...)

	if !msg.isPreHash {
		phMsg := msg.buffer.Bytes()
		msgPrime[0] = 0x0
		msgPrime = append(msgPrime, phMsg...)
	} else {
		oid := [10]byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02}
		phMsg := make([]byte, msg.outLen)
		msgPrime[0] = 0x1
		msg.hasher.Sum(phMsg)
		msgPrime = append(append(append(msgPrime, oid[:]...), msg.oid10), phMsg...)
	}

	return
}

func (k *PrivateKey) Sign2(rand io.Reader, message *Message, context []byte) (signature []byte, err error) {
	params, err := k.Instance.getParams()
	if err != nil {
		return nil, err
	}

	msgPrime, err := getMsgPrime(message, context)
	if err != nil {
		return nil, err
	}

	addRand, err := readRandom(rand, params.n)
	if err != nil {
		return nil, err
	}

	return slhSignInternal(params, k, msgPrime, addRand)
}

func (k *PrivateKey) SignDeterministic2(message *Message, context []byte) (signature []byte, err error) {
	params, err := k.Instance.getParams()
	if err != nil {
		return nil, err
	}

	msgPrime, err := getMsgPrime(message, context)
	if err != nil {
		return nil, err
	}

	return slhSignInternal(params, k, msgPrime, k.publicKey.seed)
}

func Verify2(pub *PublicKey, message *Message, context, signature []byte) bool {
	params, err := pub.Instance.getParams()
	if err != nil {
		return false
	}

	msgPrime, err := getMsgPrime(message, context)
	if err != nil {
		return false
	}

	return slhVerifyInternal(params, pub, msgPrime, signature)
}
