package slhdsa

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/sha512"

	"github.com/cloudflare/circl/internal/sha3"
	"github.com/cloudflare/circl/xof"
)

type Message struct {
	buffer    bytes.Buffer
	hasher    hasher
	isPreHash bool
	oid10     byte
	outLen    int
}

func NewMessage(msg []byte) (m Message) { _ = m.init(NoPreHash, msg); return }

func NewMessageWithPreHash(ph PreHashID) (m Message, err error) { err = m.init(ph, nil); return }

func (m *Message) Write(p []byte) (n int, err error) {
	if m.isPreHash {
		return m.hasher.Write(p)
	} else {
		return m.buffer.Write(p)
	}
}

func (m *Message) init(ph PreHashID, msg []byte) (err error) {
	switch ph {
	case NoPreHash:
		m.isPreHash = false
		m.buffer = *bytes.NewBuffer(msg)
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
		m.hasher = &sha3rw{State: sha3.NewShake256()}
	case PreHashSHAKE256:
		m.isPreHash = true
		m.oid10 = 0x0C
		m.outLen = 512 / 8
		m.hasher = &sha3rw{State: sha3.NewShake256()}
	default:
		return ErrPreHash
	}

	if m.isPreHash && msg != nil {
		_, err = m.hasher.Write(msg)
	}

	return
}

const MaxContextSize = 255

func getMsgPrime(msg *Message, context []byte) (msgPrime []byte, err error) {
	if len(context) > MaxContextSize {
		return nil, ErrContext
	}

	msgPrime = append([]byte{0, byte(len(context))}, context...)

	var phMsg []byte
	if !msg.isPreHash {
		msgPrime[0] = 0x0
		phMsg = msg.buffer.Bytes()
	} else {
		msgPrime[0] = 0x1

		oid := [11]byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02}
		oid[10] = msg.oid10
		msgPrime = append(msgPrime, oid[:]...)

		phMsg = make([]byte, msg.outLen)
		msg.hasher.SumByCopy(phMsg)
	}

	return append(msgPrime, phMsg...), nil
}

type PreHashID byte

const (
	NoPreHash       PreHashID = PreHashID(0)
	PreHashSHA256   PreHashID = PreHashID(crypto.SHA256)
	PreHashSHA512   PreHashID = PreHashID(crypto.SHA512)
	PreHashSHAKE128 PreHashID = PreHashID(xof.SHAKE128)
	PreHashSHAKE256 PreHashID = PreHashID(xof.SHAKE256)
)

func (ph PreHashID) String() string {
	switch ph {
	case NoPreHash:
		return "NoPreHash"
	case PreHashSHA256:
		return "PreHashSHA256"
	case PreHashSHA512:
		return "PreHashSHA512"
	case PreHashSHAKE128:
		return "PreHashSHAKE128"
	case PreHashSHAKE256:
		return "PreHashSHAKE256"
	default:
		return ErrPreHash.Error()
	}
}
