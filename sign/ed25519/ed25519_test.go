package ed25519_test

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/internal/test"
	eddsa "github.com/cloudflare/circl/sign/ed25519"
)

func TestWrongPublicKey(t *testing.T) {
	wrongPublicKeys := [...][eddsa.Size]byte{
		{ // y = p
			0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
		},
		{ // y > p
			0xed + 1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
		},
		{ // x^2 = u/v = (y^2-1)/(dy^2+1) is not a quadratic residue
			0x9a, 0x0a, 0xbe, 0xc6, 0x23, 0xcb, 0x5a, 0x23,
			0x4e, 0x49, 0xd8, 0x92, 0xc2, 0x72, 0xd5, 0xa8,
			0x27, 0xff, 0x42, 0x07, 0x7d, 0xe3, 0xf2, 0xb4,
			0x74, 0x75, 0x9d, 0x04, 0x34, 0xed, 0xa6, 0x70,
		},
		{ // y = 1 and x^2 = u/v = 0, and the sign of X is 1
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 | 0x80,
		},
		{ // y = -1 and x^2 = u/v = 0, and the sign of X is 1
			0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f | 0x80,
		},
	}
	sig := make([]byte, 2*eddsa.Size)
	for _, public := range wrongPublicKeys {
		got := eddsa.Verify(public[:], []byte(""), sig)
		want := false
		if got != want {
			test.ReportError(t, got, want, public)
		}
	}
}

func BenchmarkEd25519(b *testing.B) {
	msg := make([]byte, 256)
	_, _ = rand.Read(msg)

	b.Run("keygen", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			eddsa.GenerateKey(rand.Reader)
		}
	})
	b.Run("sign", func(b *testing.B) {
		keys, _ := eddsa.GenerateKey(rand.Reader)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			eddsa.Sign(keys, msg)
		}
	})
	b.Run("verify", func(b *testing.B) {
		keys, _ := eddsa.GenerateKey(rand.Reader)
		signature := eddsa.Sign(keys, msg)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			eddsa.Verify(keys.GetPublic(), msg, signature)
		}
	})
}

func Example_ed25519() {
	// import "github.com/cloudflare/circl/sign/ed25519"

	// Generating Alice's key pair
	keys, err := eddsa.GenerateKey(rand.Reader)
	if err != nil {
		panic("error on generating keys")
	}

	// Alice signs a message.
	message := []byte("A message to be signed")
	signature := eddsa.Sign(keys, message)

	// Anyone can verify the signature using Alice's public key.
	ok := eddsa.Verify(keys.GetPublic(), message, signature)
	fmt.Println(ok)
	// Output: true
}
