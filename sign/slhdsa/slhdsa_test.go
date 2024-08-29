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

func TestSlhdsa(t *testing.T) {
	for i := range supportedInstances {
		instance := supportedInstances[i]

		t.Run(instance.String(), func(t *testing.T) {
			t.Parallel()

			msg := []byte("Alice and Bob")
			ctx := []byte("this is a context string")
			ph := slhdsa.PreHashSHA512

			sk, pk, err := slhdsa.KeyGen(rand.Reader, instance)
			test.CheckNoErr(t, err, "keygen failed")

			t.Run("Keys", func(t *testing.T) { testKeys(t, instance) })
			t.Run("Pure", func(t *testing.T) { testPure(t, sk, pk, msg, ctx) })
			t.Run("Prehash", func(t *testing.T) { testPrehash(t, sk, pk, msg, ctx, ph) })
		})
	}
}

func testKeys(t *testing.T, instance slhdsa.Instance) {
	reader := sha3.NewShake128()

	reader.Reset()
	sk0, pk0, err := slhdsa.KeyGen(&reader, instance)
	test.CheckNoErr(t, err, "KeyGen failed")

	reader.Reset()
	sk1, pk1, err := slhdsa.KeyGen(&reader, instance)
	test.CheckNoErr(t, err, "KeyGen failed")

	test.CheckOk(sk0.Equal(sk1), "private key not equal", t)
	test.CheckOk(pk0.Equal(pk1), "public key not equal", t)

	test.CheckMarshal(t, sk0, sk1)
	test.CheckMarshal(t, pk0, pk1)
}

func testPure(t *testing.T, sk *slhdsa.PrivateKey, pk *slhdsa.PublicKey, msg, ctx []byte) {
	sig, err := sk.PureSign(rand.Reader, msg, ctx)
	test.CheckNoErr(t, err, "PureSign failed")

	valid := slhdsa.PureVerify(pk, msg, ctx, sig)
	test.CheckOk(valid, "PureVerify failed", t)

	sig, err = sk.PureSignDeterministic(msg, ctx)
	test.CheckNoErr(t, err, "PureSignDeterministic failed")

	valid = slhdsa.PureVerify(pk, msg, ctx, sig)
	test.CheckOk(valid, "PureVerify failed", t)
}

func testPrehash(t *testing.T, sk *slhdsa.PrivateKey, pk *slhdsa.PublicKey, msg, ctx []byte, ph slhdsa.PreHashID) {
	sig, err := sk.HashSign(rand.Reader, msg, ctx, ph)
	test.CheckNoErr(t, err, "HashSign failed")

	valid := slhdsa.HashVerify(pk, msg, ctx, sig, ph)
	test.CheckOk(valid, "HashVerify failed", t)

	sig, err = sk.HashSignDeterministic(msg, ctx, ph)
	test.CheckNoErr(t, err, "HashSignDeterministic failed")

	valid = slhdsa.HashVerify(pk, msg, ctx, sig, ph)
	test.CheckOk(valid, "HashVerify failed", t)
}

func BenchmarkSlhdsa(b *testing.B) {
	for i := range supportedInstances {
		instance := supportedInstances[i]

		b.Run(instance.String(), func(b *testing.B) {
			msg := []byte("Alice and Bob")
			ctx := []byte("this is a context string")
			ph := slhdsa.PreHashSHA512

			sk, pk, err := slhdsa.KeyGen(rand.Reader, instance)
			test.CheckNoErr(b, err, "keygen failed")

			b.Run("KeyGen", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					_, _, _ = slhdsa.KeyGen(rand.Reader, instance)
				}
			})

			benchmarkPure(b, sk, pk, msg, ctx)
			benchmarkPrehash(b, sk, pk, msg, ctx, ph)
		})
	}
}

func benchmarkPure(b *testing.B, sk *slhdsa.PrivateKey, pk *slhdsa.PublicKey, msg, ctx []byte) {
	sig, err := sk.PureSign(rand.Reader, msg, ctx)
	test.CheckNoErr(b, err, "PureSign failed")

	b.Run("PureSign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = sk.PureSign(rand.Reader, msg, ctx)
		}
	})
	b.Run("PureSignDet", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = sk.PureSignDeterministic(msg, ctx)
		}
	})
	b.Run("PureVerify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = slhdsa.PureVerify(pk, msg, ctx, sig)
		}
	})
}

func benchmarkPrehash(b *testing.B, sk *slhdsa.PrivateKey, pk *slhdsa.PublicKey, msg, ctx []byte, ph slhdsa.PreHashID) {
	sig, err := sk.HashSign(rand.Reader, msg, ctx, ph)
	test.CheckNoErr(b, err, "PureSign failed")

	b.Run("HashSign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = sk.HashSign(rand.Reader, msg, ctx, ph)
		}
	})
	b.Run("HashSignDet", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = sk.HashSignDeterministic(msg, ctx, ph)
		}
	})
	b.Run("HashVerify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = slhdsa.HashVerify(pk, msg, ctx, sig, ph)
		}
	})
}
