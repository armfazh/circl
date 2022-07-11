package frost

import "github.com/cloudflare/circl/group"

type PublicKey group.Element

type Peer struct {
	Id       uint16
	keyShare group.Scalar
}
