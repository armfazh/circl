package main

import (
	"crypto/rand"
	"log"
	"os"

	cpabe "github.com/cloudflare/circl/abe/cpabe/tkn20"
)

func main() {
	prng := rand.Reader
	publicParams, secretParams, err := cpabe.Setup(prng)
	if err != nil {
		log.Fatal(err)
	}
	ppData, err := publicParams.MarshalBinary()
	if err != nil {
		log.Fatal(err)
	}
	err = os.WriteFile("publicKey", ppData, 0o400)
	if err != nil {
		log.Fatal(err)
	}
	spData, err := secretParams.MarshalBinary()
	if err != nil {
		log.Fatal(err)
	}
	err = os.WriteFile("secretKey", spData, 0o400)
	if err != nil {
		log.Fatal(err)
	}
	attrs := cpabe.Attributes{}
	attrs.FromMap(map[string]string{"country": "NL", "EU": "true"})

	policy := cpabe.Policy{}
	err = policy.FromString("EU: true")
	if err != nil {
		log.Fatal(err)
	}
	ciphertext, err := publicParams.Encrypt(prng, policy, []byte("Be sure to drink your ovaltine!"))
	if err != nil {
		log.Fatal(err)
	}
	err = os.WriteFile("ciphertext", ciphertext, 0o400)
	if err != nil {
		log.Fatal(err)
	}
	key, err := secretParams.KeyGen(prng, attrs)
	if err != nil {
		log.Fatal(err)
	}
	keyData, err := key.MarshalBinary()
	if err != nil {
		log.Fatal(err)
	}
	err = os.WriteFile("attributeKey", keyData, 0o400)
	if err != nil {
		log.Fatal(err)
	}
}
