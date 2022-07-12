package frost

import (
	"crypto"
	_ "crypto/sha256"

	"github.com/cloudflare/circl/group"
)

type Suite struct {
	g       group.Group
	h       crypto.Hash
	context string
}

var P256 = Suite{group.P256, crypto.SHA256, "FROST-P256-SHA256-v5"}

func (s Suite) h1(m []byte) group.Scalar { return s.g.HashToScalar(m, []byte(s.context+"rho")) }
func (s Suite) h2(m []byte) group.Scalar { return s.g.HashToScalar(m, []byte(s.context+"chal")) }
func (s Suite) h4(m []byte) group.Scalar { return s.g.HashToScalar(m, []byte(s.context+"nonce")) }
func (s Suite) h3(m []byte) []byte {
	H := s.h.New()
	_, _ = H.Write([]byte(s.context + "digest"))
	_, _ = H.Write(m)
	return H.Sum(nil)
}
