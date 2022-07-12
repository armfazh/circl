package frost

import (
	"crypto"

	"github.com/cloudflare/circl/group"
)

type Suite struct {
	g         group.Group
	h         crypto.Hash
	contextSt string
}

var P256 = Suite{group.P256, crypto.SHA256, "FROST-P256-SHA256-v5"}

func (s Suite) h1(m []byte) group.Scalar { return s.g.HashToScalar(m, []byte(s.contextSt+"rho")) }
func (s Suite) h2(m []byte) group.Scalar { return s.g.HashToScalar(m, []byte(s.contextSt+"chal")) }
func (s Suite) h4(m []byte) group.Scalar { return s.g.HashToScalar(m, []byte(s.contextSt+"nonce")) }
func (s Suite) h3(m []byte) []byte {
	H := s.h.New()
	_, _ = H.Write([]byte(s.contextSt + "digest"))
	_, _ = H.Write(m)
	return H.Sum(nil)
}
