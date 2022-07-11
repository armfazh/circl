package frost

import (
	"io"

	"github.com/cloudflare/circl/group"
)

type PublicKey group.Element

type Peer struct {
	Id       uint16
	keyShare group.Scalar
}

func h1(m []byte) group.Scalar { return nil }
func h3(m []byte) []byte       { return nil }
func h2(m []byte) group.Scalar { return nil }
func h4(m []byte) group.Scalar { return nil }

func nonceGenerator(rnd io.Reader, s group.Scalar) group.Scalar {
	k := make([]byte, 32)
	_, _ = io.ReadFull(rnd, k)
	secretEnc, _ := s.MarshalBinary()
	return h4(append(append([]byte{}, k...), secretEnc...))
}
