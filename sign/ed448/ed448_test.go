package ed448_test

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/sign/ed448"
)

func BenchmarkEd448(b *testing.B) {
	msg := make([]byte, 256)
	_, _ = rand.Read(msg)

	b.Run("keygen", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ed448.GenerateKey(rand.Reader)
		}
	})
	b.Run("sign", func(b *testing.B) {
		keys, _ := ed448.GenerateKey(rand.Reader)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ed448.Sign(keys, msg)
		}
	})
	b.Run("verify", func(b *testing.B) {
		keys, _ := ed448.GenerateKey(rand.Reader)
		signature := ed448.Sign(keys, msg)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ed448.Verify(keys.GetPublic(), msg, signature)
		}
	})
}

func Example_ed448() {
	// import "github.com/cloudflare/circl/sign/ed448"

	// Generating Alice's key pair
	keys, err := ed448.GenerateKey(rand.Reader)
	if err != nil {
		panic("error on generating keys")
	}

	// Alice signs a message.
	message := []byte("A message to be signed")
	signature := ed448.Sign(keys, message)

	// Anyone can verify the signature using Alice's public key.
	ok := ed448.Verify(keys.GetPublic(), message, signature)
	fmt.Println(ok)
	// Output: true
}
