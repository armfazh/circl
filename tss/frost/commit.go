package frost

import (
	"encoding/binary"
	"errors"
	"sort"

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

func isSorted(c []Commitment) error {
	if !sort.SliceIsSorted(c, func(i, j int) bool { return c[i].Id < c[j].Id }) {
		return errors.New("frost: commitments must be sorted")
	}
	return nil
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

func calcBindingFactor(commitEncoded []byte, msg []byte) group.Scalar {
	msgHash := h3(msg)
	rho := append(append([]byte{}, commitEncoded...), msgHash...)
	return h1(rho)
}

type groupCommitment struct{ gc group.Element }

func calcGroupCommitment(g group.Group, c []Commitment, bf group.Scalar) groupCommitment {
	gh := g.NewElement()
	gb := g.NewElement()

	for _, ci := range c {
		gh.Add(gh, ci.hiding)
		gb.Add(gb, ci.binding)
	}
	gc := g.NewElement().Mul(gb, bf)
	return groupCommitment{gc.Add(gc, gh)}
}

func (gc groupCommitment) doChallenge(pubKey PublicKey, msg []byte) group.Scalar {
	gcEnc, _ := gc.gc.MarshalBinary()
	pkEnc, _ := pubKey.MarshalBinary()
	chInput := append(append(append([]byte{}, gcEnc...), pkEnc...), msg...)

	return h2(chInput)
}
