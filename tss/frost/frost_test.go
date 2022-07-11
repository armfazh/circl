package frost_test

import (
	"crypto/rand"
	"io"
	"testing"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/tss/frost"
)

func keygen(rnd io.Reader, g group.Group) (priv group.Scalar, pub group.Element) {
	priv = g.RandomNonZeroScalar(rnd)
	pub = g.NewElement().MulGen(priv)
	return
}

func TestFrost(tt *testing.T) {
	g := group.P256
	msg := []byte("it's cold here")
	t, n := uint(3), uint(5)

	// Dealer
	dealer, err := frost.NewDealer(g, t, n)
	test.CheckNoErr(tt, err, "failed to create dealer")

	privKey, pubKeyGroup := keygen(rand.Reader, g)
	peers, shareComs := dealer.Deal(rand.Reader, privKey)

	for k := uint(0); k < n; k++ {
		if k > t {
			// round 1
			nonces := make([]frost.Nonce, k)
			commits := make([]frost.Commitment, k)
			for i := range peers[:k] {
				nonces[i], commits[i] = peers[i].Commit(rand.Reader)
			}

			// round 2
			signShares := make([]*frost.SignShare, k)
			for i := range peers[:k] {
				signShares[i], err = peers[i].Sign(msg, pubKeyGroup, nonces[i], commits)
				test.CheckNoErr(tt, err, "failed to create a sign share")
			}

			// Combiner
			for i := range signShares {
				valid := signShares[i].Verify(g, pkI, commits[i], commits, pubKeyGroup, msg)
				test.CheckOk(valid == true, "invalid sign share", tt)
			}

			var groupCom struct{}
			signature, err := frost.Sign(g, groupCom, signShares)
			test.CheckNoErr(tt, err, "failed to produce signature")

			valid := frost.Verify(g, msg, signature, pubKeyGroup)
			test.CheckOk(valid == true, "invalid signature", tt)
		}
	}

}
