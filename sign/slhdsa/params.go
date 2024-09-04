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
	"github.com/cloudflare/circl/sign"
)

// [ParamID] identifies the supported parameter sets of SLH-DSA.
// Note that the zero value is an invalid identifier.
// [ParamID] with a valid identifier also implements the [sign.Scheme]
// interface, but invalid identifiers cause methods panic.
type ParamID byte

const (
	ParamIDSHA2Small128  ParamID = iota + 1 // SLH-DSA-SHA2-128s
	ParamIDSHAKESmall128                    // SLH-DSA-SHAKE-128s
	ParamIDSHA2Fast128                      // SLH-DSA-SHA2-128f
	ParamIDSHAKEFast128                     // SLH-DSA-SHAKE-128f
	ParamIDSHA2Small192                     // SLH-DSA-SHA2-192s
	ParamIDSHAKESmall192                    // SLH-DSA-SHAKE-192s
	ParamIDSHA2Fast192                      // SLH-DSA-SHA2-192f
	ParamIDSHAKEFast192                     // SLH-DSA-SHAKE-192f
	ParamIDSHA2Small256                     // SLH-DSA-SHA2-256s
	ParamIDSHAKESmall256                    // SLH-DSA-SHAKE-256s
	ParamIDSHA2Fast256                      // SLH-DSA-SHA2-256f
	ParamIDSHAKEFast256                     // SLH-DSA-SHAKE-256f
	_MaxParams
)

// [ParamIDByName] returns the [ParamID] that corresponds to the given name,
// or an error if no parameter set was found.
// See [ParamID] documentation for the specific names of each parameter set.
// Names are case insensitive.
//
// Example:
//
//	ParamIDByName("SLH-DSA-SHAKE-256s") // returns (ParamIDSHAKESmall256, nil)
func ParamIDByName(name string) (id ParamID, err error) {
	v := strings.ToLower(name)
	for i := range supportedParams {
		if strings.ToLower(supportedParams[i].name) == v {
			return supportedParams[i].id, nil
		}
	}

	return id, ErrParam
}

// IsValid returns true if the parameter set is supported.
func (id ParamID) IsValid() bool         { return 0 < id && id < _MaxParams }
func (id ParamID) Name() string          { return id.String() }
func (id ParamID) PublicKeySize() int    { return id.params().PublicKeySize() }
func (id ParamID) PrivateKeySize() int   { return id.params().PrivateKeySize() }
func (id ParamID) SignatureSize() int    { return id.params().SignatureSize() }
func (id ParamID) SeedSize() int         { return id.PrivateKeySize() }
func (id ParamID) SupportsContext() bool { return true }
func (id ParamID) String() string {
	if !id.IsValid() {
		return ErrParam.Error()
	}
	return supportedParams[id-1].name
}

func (id ParamID) params() *params {
	if !id.IsValid() {
		panic(ErrParam)
	}
	return &supportedParams[id-1]
}

func (id ParamID) UnmarshalBinaryPublicKey(b []byte) (sign.PublicKey, error) {
	k := PublicKey{ParamID: id}
	err := k.UnmarshalBinary(b)
	if err != nil {
		return nil, err
	}
	return &k, nil
}

func (id ParamID) UnmarshalBinaryPrivateKey(b []byte) (sign.PrivateKey, error) {
	k := PrivateKey{ParamID: id}
	err := k.UnmarshalBinary(b)
	if err != nil {
		return nil, err
	}
	return &k, nil
}

// params contains all the relevant constants of a parameter set.
type params struct {
	n      int     // Length of WOTS+ messages.
	hPrime int     // XMSS Merkle tree height.
	h      int     // Total height of a hypertree.
	d      int     // Hypertree has d layers of XMSS trees.
	a      int     // FORS signs a-bit messages.
	k      int     // FORS generates k private keys.
	m      int     // Used to HashMSG function.
	isSha2 bool    // True, if the hash function is SHA2, otherwise is SHAKE.
	name   string  // Name of the parameter set.
	id     ParamID // Identifier of the parameter set.
}

// Stores all the supported parameter sets.
var supportedParams = [_MaxParams - 1]params{
	{id: ParamIDSHA2Small128, n: 16, h: 63, d: 7, hPrime: 9, a: 12, k: 14, m: 30, isSha2: true, name: "SLH-DSA-SHA2-128s"},
	{id: ParamIDSHAKESmall128, n: 16, h: 63, d: 7, hPrime: 9, a: 12, k: 14, m: 30, isSha2: false, name: "SLH-DSA-SHAKE-128s"},
	{id: ParamIDSHA2Fast128, n: 16, h: 66, d: 22, hPrime: 3, a: 6, k: 33, m: 34, isSha2: true, name: "SLH-DSA-SHA2-128f"},
	{id: ParamIDSHAKEFast128, n: 16, h: 66, d: 22, hPrime: 3, a: 6, k: 33, m: 34, isSha2: false, name: "SLH-DSA-SHAKE-128f"},
	{id: ParamIDSHA2Small192, n: 24, h: 63, d: 7, hPrime: 9, a: 14, k: 17, m: 39, isSha2: true, name: "SLH-DSA-SHA2-192s"},
	{id: ParamIDSHAKESmall192, n: 24, h: 63, d: 7, hPrime: 9, a: 14, k: 17, m: 39, isSha2: false, name: "SLH-DSA-SHAKE-192s"},
	{id: ParamIDSHA2Fast192, n: 24, h: 66, d: 22, hPrime: 3, a: 8, k: 33, m: 42, isSha2: true, name: "SLH-DSA-SHA2-192f"},
	{id: ParamIDSHAKEFast192, n: 24, h: 66, d: 22, hPrime: 3, a: 8, k: 33, m: 42, isSha2: false, name: "SLH-DSA-SHAKE-192f"},
	{id: ParamIDSHA2Small256, n: 32, h: 64, d: 8, hPrime: 8, a: 14, k: 22, m: 47, isSha2: true, name: "SLH-DSA-SHA2-256s"},
	{id: ParamIDSHAKESmall256, n: 32, h: 64, d: 8, hPrime: 8, a: 14, k: 22, m: 47, isSha2: false, name: "SLH-DSA-SHAKE-256s"},
	{id: ParamIDSHA2Fast256, n: 32, h: 68, d: 17, hPrime: 4, a: 9, k: 35, m: 49, isSha2: true, name: "SLH-DSA-SHA2-256f"},
	{id: ParamIDSHAKEFast256, n: 32, h: 68, d: 17, hPrime: 4, a: 9, k: 35, m: 49, isSha2: false, name: "SLH-DSA-SHAKE-256f"},
}

// See FIPS-205, Section 11.1 and Section 11.2.
func (p *params) PRFMsg(out, skPrf, optRand, msg []byte) {
	if p.isSha2 {
		var h crypto.Hash
		if p.n == 16 {
			h = crypto.SHA256
		} else {
			h = crypto.SHA512
		}

		mac := hmac.New(h.New, skPrf)
		concat(mac, optRand, msg)
		mac.Sum(out[:0])
	} else {
		state := sha3.NewShake256()
		concat(&state, skPrf, optRand, msg)
		_, _ = state.Read(out)
	}
}

// See FIPS-205, Section 11.1 and Section 11.2.
func (p *params) HashMsg(out, r, pkSeed, pkRoot, msg []byte) {
	if p.isSha2 {
		var state hash.Hash
		if p.n == 16 {
			state = sha256.New()
		} else {
			state = sha512.New()
		}

		hLen := state.Size()
		mgfSeed := make([]byte, 2*p.n+hLen+4)
		c := cursor(mgfSeed)
		copy(c.Next(p.n), r)
		copy(c.Next(p.n), pkSeed)
		sumInter := c.Next(hLen)

		concat(state, r, pkSeed, pkRoot, msg)
		state.Sum(sumInter[:0])
		p.mgf1(out, mgfSeed)
	} else {
		state := sha3.NewShake256()
		concat(&state, r, pkSeed, pkRoot, msg)
		_, _ = state.Read(out)
	}
}

// MGF1 described in Appendix B.2.1 of RFC 8017.
func (p *params) mgf1(out, mgfSeed []byte) {
	var hLen int
	var hashFn func(out, in []byte)
	if p.n == 16 {
		hLen = sha256.Size
		hashFn = sha256sum
	} else {
		hLen = sha512.Size
		hashFn = sha512sum
	}

	offset := 0
	end := (len(out) + hLen - 1) / hLen
	counterBytes := mgfSeed[len(mgfSeed)-4:]
	for counter := 0; counter < end; counter++ {
		binary.BigEndian.PutUint32(counterBytes, uint32(counter))
		hashFn(out[offset:], mgfSeed)
		offset += hLen
	}
}

func concat(w io.Writer, list ...[]byte) {
	for i := range list {
		_, err := w.Write(list[i])
		if err != nil {
			panic(ErrWriting)
		}
	}
}
