package rsa

import (
	"crypto/rand"
	"math/big"
	"testing"
)

func marshalTestKeyShare(share KeyShare, t *testing.T) {
	marshall, err := share.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	share2 := KeyShare{}
	err = share2.UnmarshalBinary(marshall)
	if err != nil {
		t.Fatal(err)
	}

	if share.Players != share2.Players {
		t.Fatalf("Players did not match, expected %d, found %d", share.Players, share2.Players)
	}

	if share.Threshold != share2.Threshold {
		t.Fatalf("Threshold did not match, expected %d, found %d", share.Threshold, share2.Threshold)
	}

	if share.Index != share2.Index {
		t.Fatalf("Index did not match, expected %d, found %d", share.Index, share2.Index)
	}

	if share.twoDeltaSi.Cmp(&share2.twoDeltaSi) != 0 {
		t.Fatalf("twoDeltaSi did not match, expected %v, found %v", share.twoDeltaSi, share2.twoDeltaSi)
	}

	if share.si.Cmp(&share2.si) != 0 {
		t.Fatalf("si did not match, expected %v, found %v", share.si.Bytes(), share2.si.Bytes())
	}
}

func unmarshalKeyShareTest(t *testing.T, input []byte) {
	share := KeyShare{}
	err := share.UnmarshalBinary(input)
	if err == nil {
		t.Fatalf("unmarshall succeeded when it shouldn't have")
	}
}

func TestMarshallKeyShare(t *testing.T) {
	marshalTestKeyShare(KeyShare{
		si:         *big.NewInt(10),
		twoDeltaSi: *big.NewInt(20),
		Index:      30,
		Threshold:  10,
		Players:    2,
	}, t)

	marshalTestKeyShare(KeyShare{
		si:         *big.NewInt(10),
		twoDeltaSi: *big.NewInt(20),
		Index:      30,
		Threshold:  0,
		Players:    200,
	}, t)

	marshalTestKeyShare(KeyShare{
		si:         *big.NewInt(0),
		twoDeltaSi: *big.NewInt(0),
		Index:      0,
		Threshold:  0,
		Players:    0,
	}, t)

	unmarshalKeyShareTest(t, []byte{})
	unmarshalKeyShareTest(t, []byte{1, 0, 1})
	unmarshalKeyShareTest(t, []byte{1, 0, 1})
	unmarshalKeyShareTest(t, []byte{0, 1, 0, 1, 0, 1})
	unmarshalKeyShareTest(t, []byte{0, 1, 0, 1, 0, 1, 0, 1})
	unmarshalKeyShareTest(t, []byte{0, 1, 0, 1, 0, 1, 0})
	unmarshalKeyShareTest(t, []byte{0, 1, 0, 1, 0, 1, 0, 2, 1})
	unmarshalKeyShareTest(t, []byte{0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0})
	unmarshalKeyShareTest(t, []byte{0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1})
}

func TestMarshallKeyShareFull(t *testing.T) {
	const players = 3
	const threshold = 2
	const bits = 1024

	key, err := GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := Deal(rand.Reader, players, threshold, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, share := range keys {
		marshalTestKeyShare(share, t)
	}
}
