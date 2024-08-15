package slhdsa

import (
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"strings"

	"github.com/cloudflare/circl/internal/sha3"
)

type params struct {
	n      uint
	h      uint
	d      uint
	hPrime uint
	a      uint
	k      uint
	m      uint
	pkLen  uint
	sigLen uint
	isSha2 bool
	ins    Instance
	name   string
}

type Instance uint8

const (
	SlhdsaSHA2Small128 Instance = iota
	SlhdsaSHAKESmall128
	SlhdsaSHA2Fast128
	SlhdsaSHAKEFast128
	SlhdsaSHA2Small192
	SlhdsaSHAKESmall192
	SlhdsaSHA2Fast192
	SlhdsaSHAKEFast192
	SlhdsaSHA2Small256
	SlhdsaSHAKESmall256
	SlhdsaSHA2Fast256
	SlhdsaSHAKEFast256
	_MaxInstances
)

func (i Instance) Validate() (err error) {
	if !(i < _MaxInstances) {
		err = ErrInstance
	}
	return
}

// InstanceByName returns the instance with the given name, or
// an error if the instance name was not found.
//
// Names are case insensitive.
func InstanceByName(name string) (ins Instance, err error) {
	v := strings.ToLower(name)
	for i := range instances {
		if strings.ToLower(instances[i].name) == v {
			return instances[i].ins, nil
		}
	}
	return ins, ErrInstance
}

type state struct {
	*params
	hasher
}

func (i Instance) String() string {
	err := i.Validate()
	if err != nil {
		return "invalid instance"
	}
	return instances[i].name
}

func (i Instance) newState() (s *state, err error) {
	err = i.Validate()
	if err != nil {
		return
	}

	s = new(state)
	s.params = &instances[i]
	if s.params.isSha2 {
		if s.params.n == 16 {
			s.hasher = &sha2Fn{n: s.params.n, m: s.params.m, padLen: 64, sha2Fn: crypto.SHA256, state: sha256.New()}
		} else {
			s.hasher = &sha2Fn{n: s.params.n, m: s.params.m, padLen: 128, sha2Fn: crypto.SHA512, state: sha512.New()}
		}
	} else {
		s.hasher = &shakeFn{n: s.params.n, m: s.params.m, state: sha3.NewShake256()}
	}

	return
}

var instances = [_MaxInstances]params{
	{ins: SlhdsaSHA2Small128, n: 16, h: 63, d: 7, hPrime: 9, a: 12, k: 14, m: 30, pkLen: 32, sigLen: 7856, isSha2: true, name: "SLH-DSA-SHA2-128s"},
	{ins: SlhdsaSHAKESmall128, n: 16, h: 63, d: 7, hPrime: 9, a: 12, k: 14, m: 30, pkLen: 32, sigLen: 7856, isSha2: false, name: "SLH-DSA-SHAKE-128s"},
	{ins: SlhdsaSHA2Fast128, n: 16, h: 66, d: 22, hPrime: 3, a: 6, k: 33, m: 34, pkLen: 32, sigLen: 17088, isSha2: true, name: "SLH-DSA-SHA2-128f"},
	{ins: SlhdsaSHAKEFast128, n: 16, h: 66, d: 22, hPrime: 3, a: 6, k: 33, m: 34, pkLen: 32, sigLen: 17088, isSha2: false, name: "SLH-DSA-SHAKE-128f"},
	{ins: SlhdsaSHA2Small192, n: 24, h: 63, d: 7, hPrime: 9, a: 14, k: 17, m: 39, pkLen: 48, sigLen: 16224, isSha2: true, name: "SLH-DSA-SHA2-192s"},
	{ins: SlhdsaSHAKESmall192, n: 24, h: 63, d: 7, hPrime: 9, a: 14, k: 17, m: 39, pkLen: 48, sigLen: 16224, isSha2: false, name: "SLH-DSA-SHAKE-192s"},
	{ins: SlhdsaSHA2Fast192, n: 24, h: 66, d: 22, hPrime: 3, a: 8, k: 33, m: 42, pkLen: 48, sigLen: 35664, isSha2: true, name: "SLH-DSA-SHA2-192f"},
	{ins: SlhdsaSHAKEFast192, n: 24, h: 66, d: 22, hPrime: 3, a: 8, k: 33, m: 42, pkLen: 48, sigLen: 35664, isSha2: false, name: "SLH-DSA-SHAKE-192f"},
	{ins: SlhdsaSHA2Small256, n: 32, h: 64, d: 8, hPrime: 8, a: 14, k: 22, m: 47, pkLen: 64, sigLen: 29792, isSha2: true, name: "SLH-DSA-SHA2-256s"},
	{ins: SlhdsaSHAKESmall256, n: 32, h: 64, d: 8, hPrime: 8, a: 14, k: 22, m: 47, pkLen: 64, sigLen: 29792, isSha2: false, name: "SLH-DSA-SHAKE-256s"},
	{ins: SlhdsaSHA2Fast256, n: 32, h: 68, d: 17, hPrime: 4, a: 9, k: 35, m: 49, pkLen: 64, sigLen: 49856, isSha2: true, name: "SLH-DSA-SHA2-256f"},
	{ins: SlhdsaSHAKEFast256, n: 32, h: 68, d: 17, hPrime: 4, a: 9, k: 35, m: 49, pkLen: 64, sigLen: 49856, isSha2: false, name: "SLH-DSA-SHAKE-256f"},
}
