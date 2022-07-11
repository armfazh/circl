package frost

import (
	"encoding/binary"
	"sort"

	"github.com/cloudflare/circl/group"
)

type commitment struct {
	id              uint16
	hiding, binding group.Element
}

func (c commitment) MarshalBinary() ([]byte, error) {
	bytes := (&[2]byte{})[:]
	binary.BigEndian.PutUint16(bytes, c.id)

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

func bindingFactor(commitEncoded []byte, msg []byte) group.Scalar {
	msgHash := h3(msg)
	rho := append(append([]byte{}, commitEncoded...), msgHash...)
	return h1(rho)
}

type groupCommitment struct{ gc group.Element }

func getGroupCommitment(g group.Group, c []commitment, bf group.Scalar) groupCommitment {
	if !sort.SliceIsSorted(c, func(i, j int) bool { return c[i].id < c[j].id }) {
		panic("commitments must be sorted")
	}

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
