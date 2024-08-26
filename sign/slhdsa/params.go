package slhdsa

import (
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"strings"

	"github.com/cloudflare/circl/internal/sha3"
)

type Instance int

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
	if i.Validate() != nil {
		return ErrInstance.Error()
	}
	return instances[i].name
}

func (i Instance) Validate() (err error) {
	if !(i < _MaxInstances) {
		err = ErrInstance
	}
	return
}

func (i Instance) newState() (s *state, err error) {
	err = i.Validate()
	if err != nil {
		return
	}

	return instances[i].newState()
}

type params struct {
	n      int
	h      int
	d      int
	hPrime int
	a      int
	k      int
	m      int
	sigLen int
	isSha2 bool
	ins    Instance
	name   string
}

func (p *params) newState() (s *state, err error) {
	s = &state{params: p}

	if p.isSha2 {
		if p.n == 16 {
			s.hasher = &sha2Fn{
				n:      p.n,
				padLen: 64,
				hmacFn: crypto.SHA256,
				state:  sha256.New(),
			}
		} else {
			s.hasher = &sha2Fn{
				n:      p.n,
				padLen: 128,
				hmacFn: crypto.SHA512,
				state:  sha512.New(),
			}
		}
	} else {
		s.hasher = &shakeFn{sha3.NewShake256()}
	}

	s.prf.init(p)
	s.f.init(p)
	s.t.init(p)

	return
}

var instances = [_MaxInstances]params{
	{ins: SlhdsaSHA2Small128, n: 16, h: 63, d: 7, hPrime: 9, a: 12, k: 14, m: 30, sigLen: 7856, isSha2: true, name: "SLH-DSA-SHA2-128s"},
	{ins: SlhdsaSHAKESmall128, n: 16, h: 63, d: 7, hPrime: 9, a: 12, k: 14, m: 30, sigLen: 7856, isSha2: false, name: "SLH-DSA-SHAKE-128s"},
	{ins: SlhdsaSHA2Fast128, n: 16, h: 66, d: 22, hPrime: 3, a: 6, k: 33, m: 34, sigLen: 17088, isSha2: true, name: "SLH-DSA-SHA2-128f"},
	{ins: SlhdsaSHAKEFast128, n: 16, h: 66, d: 22, hPrime: 3, a: 6, k: 33, m: 34, sigLen: 17088, isSha2: false, name: "SLH-DSA-SHAKE-128f"},
	{ins: SlhdsaSHA2Small192, n: 24, h: 63, d: 7, hPrime: 9, a: 14, k: 17, m: 39, sigLen: 16224, isSha2: true, name: "SLH-DSA-SHA2-192s"},
	{ins: SlhdsaSHAKESmall192, n: 24, h: 63, d: 7, hPrime: 9, a: 14, k: 17, m: 39, sigLen: 16224, isSha2: false, name: "SLH-DSA-SHAKE-192s"},
	{ins: SlhdsaSHA2Fast192, n: 24, h: 66, d: 22, hPrime: 3, a: 8, k: 33, m: 42, sigLen: 35664, isSha2: true, name: "SLH-DSA-SHA2-192f"},
	{ins: SlhdsaSHAKEFast192, n: 24, h: 66, d: 22, hPrime: 3, a: 8, k: 33, m: 42, sigLen: 35664, isSha2: false, name: "SLH-DSA-SHAKE-192f"},
	{ins: SlhdsaSHA2Small256, n: 32, h: 64, d: 8, hPrime: 8, a: 14, k: 22, m: 47, sigLen: 29792, isSha2: true, name: "SLH-DSA-SHA2-256s"},
	{ins: SlhdsaSHAKESmall256, n: 32, h: 64, d: 8, hPrime: 8, a: 14, k: 22, m: 47, sigLen: 29792, isSha2: false, name: "SLH-DSA-SHAKE-256s"},
	{ins: SlhdsaSHA2Fast256, n: 32, h: 68, d: 17, hPrime: 4, a: 9, k: 35, m: 49, sigLen: 49856, isSha2: true, name: "SLH-DSA-SHA2-256f"},
	{ins: SlhdsaSHAKEFast256, n: 32, h: 68, d: 17, hPrime: 4, a: 9, k: 35, m: 49, sigLen: 49856, isSha2: false, name: "SLH-DSA-SHAKE-256f"},
}
