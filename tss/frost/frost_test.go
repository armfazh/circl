package frost_test

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/tss/frost"
)

func TestFrost(tt *testing.T) {
	suite := frost.P256
	t, n := uint(3), uint(5)

	// Dealer
	dealer, err := frost.NewDealer(suite, t, n)
	test.CheckNoErr(tt, err, "failed to create dealer")

	privKey := frost.GenerateKey(suite, rand.Reader)
	pubKeyGroup := privKey.Public()
	peers, shareCommits := dealer.Deal(rand.Reader, privKey)

	// every peer can validate its own keyShare.
	for i := range peers {
		valid := peers[i].CheckKeyShare(shareCommits)
		test.CheckOk(valid == true, "invalid key share", tt)
	}

	for k := uint(0); k < 5; k++ {
		if k > t {
			// round 1
			nonces := make([]*frost.Nonce, k)
			commits := make([]*frost.Commitment, k)
			pkSigners := make([]*frost.PublicKey, k)
			for i := range peers[:k] {
				nonces[i], commits[i], err = peers[i].Commit(rand.Reader)
				test.CheckNoErr(tt, err, "failed to commit")
				pkSigners[i] = peers[i].Public()
			}

			// round 2
			msg := []byte("it's cold here")
			signShares := make([]*frost.SignShare, k)
			for i := range peers[:k] {
				signShares[i], err = peers[i].Sign(msg, pubKeyGroup, nonces[i], commits)
				test.CheckNoErr(tt, err, "failed to create a sign share")
			}

			// Combiner
			for i := range signShares {
				valid := signShares[i].Verify(suite, pkSigners[i], commits[i], commits, pubKeyGroup, msg)
				test.CheckOk(valid == true, "invalid sign share", tt)
			}

			signature, err := frost.Sign(suite, msg, commits, signShares)
			test.CheckNoErr(tt, err, "failed to produce signature")

			// anyone can verify
			valid := frost.Verify(suite, pubKeyGroup, msg, signature)
			test.CheckOk(valid == true, "invalid signature", tt)
		}
	}
}
