package slhdsa

import (
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"hash"
	"io"
	"strings"

	"github.com/cloudflare/circl/internal/sha3"
)

type Instance byte

const (
	SlhdsaSHA2Small128  Instance = iota // SLH-DSA-SHA2-128s
	SlhdsaSHAKESmall128                 // SLH-DSA-SHAKE-128s
	SlhdsaSHA2Fast128                   // SLH-DSA-SHA2-128f
	SlhdsaSHAKEFast128                  // SLH-DSA-SHAKE-128f
	SlhdsaSHA2Small192                  // SLH-DSA-SHA2-192s
	SlhdsaSHAKESmall192                 // SLH-DSA-SHAKE-192s
	SlhdsaSHA2Fast192                   // SLH-DSA-SHA2-192f
	SlhdsaSHAKEFast192                  // SLH-DSA-SHAKE-192f
	SlhdsaSHA2Small256                  // SLH-DSA-SHA2-256s
	SlhdsaSHAKESmall256                 // SLH-DSA-SHAKE-256s
	SlhdsaSHA2Fast256                   // SLH-DSA-SHA2-256f
	SlhdsaSHAKEFast256                  // SLH-DSA-SHAKE-256f
	_MaxInstances
)

// InstanceByName returns the instance with the given name, or
// an error if the instance name was not found. Names are case insensitive.
func InstanceByName(name string) (ins Instance, err error) {
	v := strings.ToLower(name)
	for i := range instances {
		if strings.ToLower(instances[i].name) == v {
			return instances[i].ins, nil
		}
	}
	return _MaxInstances, ErrInstance
}

func (i Instance) String() string {
	param, err := i.getParams()
	if err != nil {
		return err.Error()
	}
	return param.name
}

func (i Instance) Validate() (err error) {
	if !(i < _MaxInstances) {
		err = ErrInstance
	}
	return
}

func (i Instance) getParams() (p *params, err error) {
	err = i.Validate()
	if err != nil {
		return nil, err
	}

	return &instances[i], nil
}

type params struct {
	n      int
	h      int
	d      int
	hPrime int
	a      int
	k      int
	m      int
	isSha2 bool
	ins    Instance
	name   string
}

var instances = [_MaxInstances]params{
	{ins: SlhdsaSHA2Small128, n: 16, h: 63, d: 7, hPrime: 9, a: 12, k: 14, m: 30, isSha2: true, name: "SLH-DSA-SHA2-128s"},
	{ins: SlhdsaSHAKESmall128, n: 16, h: 63, d: 7, hPrime: 9, a: 12, k: 14, m: 30, isSha2: false, name: "SLH-DSA-SHAKE-128s"},
	{ins: SlhdsaSHA2Fast128, n: 16, h: 66, d: 22, hPrime: 3, a: 6, k: 33, m: 34, isSha2: true, name: "SLH-DSA-SHA2-128f"},
	{ins: SlhdsaSHAKEFast128, n: 16, h: 66, d: 22, hPrime: 3, a: 6, k: 33, m: 34, isSha2: false, name: "SLH-DSA-SHAKE-128f"},
	{ins: SlhdsaSHA2Small192, n: 24, h: 63, d: 7, hPrime: 9, a: 14, k: 17, m: 39, isSha2: true, name: "SLH-DSA-SHA2-192s"},
	{ins: SlhdsaSHAKESmall192, n: 24, h: 63, d: 7, hPrime: 9, a: 14, k: 17, m: 39, isSha2: false, name: "SLH-DSA-SHAKE-192s"},
	{ins: SlhdsaSHA2Fast192, n: 24, h: 66, d: 22, hPrime: 3, a: 8, k: 33, m: 42, isSha2: true, name: "SLH-DSA-SHA2-192f"},
	{ins: SlhdsaSHAKEFast192, n: 24, h: 66, d: 22, hPrime: 3, a: 8, k: 33, m: 42, isSha2: false, name: "SLH-DSA-SHAKE-192f"},
	{ins: SlhdsaSHA2Small256, n: 32, h: 64, d: 8, hPrime: 8, a: 14, k: 22, m: 47, isSha2: true, name: "SLH-DSA-SHA2-256s"},
	{ins: SlhdsaSHAKESmall256, n: 32, h: 64, d: 8, hPrime: 8, a: 14, k: 22, m: 47, isSha2: false, name: "SLH-DSA-SHAKE-256s"},
	{ins: SlhdsaSHA2Fast256, n: 32, h: 68, d: 17, hPrime: 4, a: 9, k: 35, m: 49, isSha2: true, name: "SLH-DSA-SHA2-256f"},
	{ins: SlhdsaSHAKEFast256, n: 32, h: 68, d: 17, hPrime: 4, a: 9, k: 35, m: 49, isSha2: false, name: "SLH-DSA-SHAKE-256f"},
}

func (p *params) PRFMsg(out, skPrf, optRand, msg []byte) (err error) {
	if p.isSha2 {
		var h crypto.Hash
		if p.n == 16 {
			h = crypto.SHA256
		} else {
			h = crypto.SHA512
		}

		mac := hmac.New(h.New, skPrf)
		err = concat(mac, optRand, msg)
		if err != nil {
			return
		}

		var sum [sha512.Size]byte
		copy(out, mac.Sum(sum[:0]))
	} else {
		state := sha3.NewShake256()
		err = concat(&state, skPrf, optRand, msg)
		if err != nil {
			return
		}
		_, err = state.Read(out)
	}

	return
}

func (p *params) HashMsg(out, r, pkSeed, pkRoot, msg []byte) (err error) {
	if p.isSha2 {
		var state hash.Hash
		if p.n == 16 {
			state = sha256.New()
		} else {
			state = sha512.New()
		}

		err = concat(state, r, pkSeed, pkRoot, msg)
		if err != nil {
			return
		}

		mgfSeed := append(append(make([]byte, 0, 2*p.n), r...), pkSeed...)
		err = mgf1(state, out, state.Sum(mgfSeed))
	} else {
		state := sha3.NewShake256()
		err = concat(&state, r, pkSeed, pkRoot, msg)
		if err != nil {
			return
		}

		_, err = state.Read(out)
	}
	return
}

func mgf1(state hash.Hash, out, mgfSeed []byte) (err error) {
	hLen := state.Size()
	end := (len(out) + hLen - 1) / hLen
	buf := make([]byte, 0, end*hLen)
	var counterBytes [4]byte
	for counter := 0; counter < end; counter++ {
		state.Reset()
		binary.BigEndian.PutUint32(counterBytes[:], uint32(counter))
		err = concat(state, mgfSeed, counterBytes[:])
		if err != nil {
			return
		}

		buf = state.Sum(buf)
	}
	copy(out, buf)
	return
}

func concat(w io.Writer, list ...[]byte) (err error) {
	for i := range list {
		_, err = w.Write(list[i])
		if err != nil {
			return
		}
	}
	return
}
