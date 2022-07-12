package frost

import (
	"encoding/binary"
	"io"

	"github.com/cloudflare/circl/group"
)

type Nonce struct {
	Id              uint16
	hiding, binding group.Scalar
}

func (s Suite) nonceGenerate(rnd io.Reader, secret group.Scalar) (group.Scalar, error) {
	k := make([]byte, 32)
	_, err := io.ReadFull(rnd, k)
	if err != nil {
		return nil, err
	}
	secretEnc, err := secret.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return s.hasher.h4(append(append([]byte{}, k...), secretEnc...)), nil
}

type Commitment struct {
	Id              uint16
	hiding, binding group.Element
}

func (c Commitment) MarshalBinary() ([]byte, error) {
	bytes := (&[2]byte{})[:]
	binary.BigEndian.PutUint16(bytes, c.Id)

	h, err := c.hiding.MarshalBinaryCompress()
	if err != nil {
		return nil, err
	}
	b, err := c.binding.MarshalBinaryCompress()
	if err != nil {
		return nil, err
	}

	return append(append(bytes, h...), b...), nil
}

func encodeComs(coms []*Commitment) ([]byte, error) {
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

func (s Suite) getBindingFactor(commitEncoded []byte, msg []byte) group.Scalar {
	msgHash := s.hasher.h3(msg)
	rho := append(append([]byte{}, commitEncoded...), msgHash...)
	return s.hasher.h1(rho)
}

func (s Suite) getGroupCommitment(c []*Commitment, bf group.Scalar) group.Element {
	gh := s.g.NewElement()
	gb := s.g.NewElement()
	for i := range c {
		gh.Add(gh, c[i].hiding)
		gb.Add(gb, c[i].binding)
	}
	gc := s.g.NewElement().Mul(gb, bf)
	return gc.Add(gc, gh)
}

func (s Suite) getChallenge(groupCom group.Element, pubKey *PublicKey, msg []byte) (group.Scalar, error) {
	gcEnc, err := groupCom.MarshalBinaryCompress()
	if err != nil {
		return nil, err
	}
	pkEnc, err := pubKey.key.MarshalBinaryCompress()
	if err != nil {
		return nil, err
	}
	chInput := append(append(append([]byte{}, gcEnc...), pkEnc...), msg...)

	return s.hasher.h2(chInput), nil
}
