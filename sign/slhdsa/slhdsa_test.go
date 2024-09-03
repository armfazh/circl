package slhdsa_test

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/internal/sha3"
	"github.com/cloudflare/circl/internal/test"
	"github.com/cloudflare/circl/sign/slhdsa"
)

var supportedInstances = [12]slhdsa.Instance{
	slhdsa.SlhdsaSHA2Small128,
	slhdsa.SlhdsaSHAKESmall128,
	slhdsa.SlhdsaSHA2Fast128,
	slhdsa.SlhdsaSHAKEFast128,
	slhdsa.SlhdsaSHA2Small192,
	slhdsa.SlhdsaSHAKESmall192,
	slhdsa.SlhdsaSHA2Fast192,
	slhdsa.SlhdsaSHAKEFast192,
	slhdsa.SlhdsaSHA2Small256,
	slhdsa.SlhdsaSHAKESmall256,
	slhdsa.SlhdsaSHA2Fast256,
	slhdsa.SlhdsaSHAKEFast256,
}

var supportedPrehashIDs = [5]slhdsa.PreHashID{
	slhdsa.NoPreHash,
	slhdsa.PreHashSHA256,
	slhdsa.PreHashSHA512,
	slhdsa.PreHashSHAKE128,
	slhdsa.PreHashSHAKE256,
}

func TestSlhdsa(t *testing.T) {
	for i := range supportedInstances {
		instance := supportedInstances[i]

		t.Run(instance.String(), func(t *testing.T) {
			t.Parallel()

			msg := []byte("Alice and Bob")
			ctx := []byte("this is a context string")

			pub, priv, err := slhdsa.GenerateKey(rand.Reader, instance)
			test.CheckNoErr(t, err, "keygen failed")

			t.Run("Keys", func(t *testing.T) { testKeys(t, instance) })

			for j := range supportedPrehashIDs {
				ph := supportedPrehashIDs[j]
				t.Run("Sign/"+ph.String(), func(t *testing.T) { testSign(t, pub, priv, msg, ctx, ph) })
			}
		})
	}
}

func testKeys(t *testing.T, instance slhdsa.Instance) {
	reader := sha3.NewShake128()

	reader.Reset()
	pub0, priv0, err := slhdsa.GenerateKey(&reader, instance)
	test.CheckNoErr(t, err, "GenerateKey failed")

	reader.Reset()
	pub1, priv1, err := slhdsa.GenerateKey(&reader, instance)
	test.CheckNoErr(t, err, "GenerateKey failed")

	test.CheckOk(priv0.Equal(priv1), "private key not equal", t)
	test.CheckOk(pub0.Equal(pub1), "public key not equal", t)

	test.CheckMarshal(t, priv0, priv1)
	test.CheckMarshal(t, pub0, pub1)
}

func testSign(t *testing.T, pk *slhdsa.PublicKey, sk *slhdsa.PrivateKey, msg, ctx []byte, ph slhdsa.PreHashID) {
	m, err := slhdsa.NewMessageWithPreHash(ph)
	test.CheckNoErr(t, err, "NewMessageWithPreHash failed")

	_, err = m.Write(msg)
	test.CheckNoErr(t, err, "Write message failed")

	sig, err := sk.SignRandomized(rand.Reader, &m, ctx)
	test.CheckNoErr(t, err, "SignRandomized failed")

	valid := slhdsa.Verify(pk, &m, ctx, sig)
	test.CheckOk(valid, "Verify failed", t)

	sig, err = sk.SignDeterministic(&m, ctx)
	test.CheckNoErr(t, err, "SignDeterministic failed")

	valid = slhdsa.Verify(pk, &m, ctx, sig)
	test.CheckOk(valid, "Verify failed", t)
}

func BenchmarkSlhdsa(b *testing.B) {
	for i := range supportedInstances {
		instance := supportedInstances[i]

		b.Run(instance.String(), func(b *testing.B) {
			msg := []byte("Alice and Bob")
			ctx := []byte("this is a context string")

			pub, priv, err := slhdsa.GenerateKey(rand.Reader, instance)
			test.CheckNoErr(b, err, "GenerateKey failed")

			b.Run("GenerateKey", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					_, _, _ = slhdsa.GenerateKey(rand.Reader, instance)
				}
			})
			for j := range supportedPrehashIDs {
				ph := supportedPrehashIDs[j]
				b.Run(ph.String(), func(b *testing.B) { benchmarkSign(b, pub, priv, msg, ctx, ph) })
			}
		})
	}
}

func benchmarkSign(b *testing.B, pk *slhdsa.PublicKey, sk *slhdsa.PrivateKey, msg, ctx []byte, ph slhdsa.PreHashID) {
	m, err := slhdsa.NewMessageWithPreHash(ph)
	test.CheckNoErr(b, err, "NewMessageWithPreHash failed")

	_, err = m.Write(msg)
	test.CheckNoErr(b, err, "Write message failed")

	sig, err := sk.SignRandomized(rand.Reader, &m, ctx)
	test.CheckNoErr(b, err, "Pure SignRandomized failed")

	b.Run("SignRandomized", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = sk.SignRandomized(rand.Reader, &m, ctx)
		}
	})
	b.Run("SignDeterministic", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = sk.SignDeterministic(&m, ctx)
		}
	})
	b.Run("Verify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = slhdsa.Verify(pk, &m, ctx, sig)
		}
	})
}
