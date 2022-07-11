package frost

import (
	"encoding/binary"

	"github.com/cloudflare/circl/group"
)

type Nonce struct {
	Id              uint16
	hiding, binding group.Scalar
}

type Commitment struct {
	Id              uint16
	hiding, binding group.Element
}

func (c Commitment) MarshalBinary() ([]byte, error) {
	bytes := (&[2]byte{})[:]
	binary.BigEndian.PutUint16(bytes, c.Id)

	h, err := c.hiding.MarshalBinary()
	if err != nil {
		return nil, err
	}
	b, err := c.binding.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return append(append(bytes, h...), b...), nil
}

func encodeComs(coms []Commitment) ([]byte, error) {
	var out []byte
	for i := range coms {
		cEnc, err := coms[i].MarshalBinary()
		if err != nil {
			return nil, err
		}
		out = append(out, cEnc...)
	}
	return out, nil
}

func getBindingFactor(commitEncoded []byte, msg []byte) group.Scalar {
	msgHash := h3(msg)
	rho := append(append([]byte{}, commitEncoded...), msgHash...)
	return h1(rho)
}

func getGroupCommitment(g group.Group, c []Commitment, bf group.Scalar) group.Element {
	gh := g.NewElement()
	gb := g.NewElement()

	for _, ci := range c {
		gh.Add(gh, ci.hiding)
		gb.Add(gb, ci.binding)
	}
	gc := g.NewElement().Mul(gb, bf)
	return gc.Add(gc, gh)
}

func getChallenge(groupCom group.Element, pubKey PublicKey, msg []byte) (group.Scalar, error) {
	gcEnc, err := groupCom.MarshalBinary()
	if err != nil {
		return nil, err
	}
	pkEnc, err := pubKey.MarshalBinary()
	if err != nil {
		return nil, err
	}
	chInput := append(append(append([]byte{}, gcEnc...), pkEnc...), msg...)

	return h2(chInput), nil
}
