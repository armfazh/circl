package ed448_test

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/sign/ed448"
)

func BenchmarkEd448(b *testing.B) {
	msg := make([]byte, 128)
	ctx := make([]byte, 128)
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
			ed448.Sign(keys, msg, ctx)
		}
	})
	b.Run("verify", func(b *testing.B) {
		keys, _ := ed448.GenerateKey(rand.Reader)
		sig := ed448.Sign(keys, msg, ctx)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			ed448.Verify(keys.GetPublic(), msg, ctx, sig)
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
	context := []byte("This is a context string")
	signature := ed448.Sign(keys, message, context)

	// Anyone can verify the signature using Alice's public key.
	ok := ed448.Verify(keys.GetPublic(), message, context, signature)
	fmt.Println(ok)
	// Output: true
}
