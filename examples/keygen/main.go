// Generates a key pair for the given kid: writes the public key to $KEYS_DIR/<kid>.pub
// and prints the issuer env vars. Usage: go run ./examples/keygen 2026-01
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: keygen <kid>")
	}
	kid := os.Args[1]

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	dir := os.Getenv("KEYS_DIR")
	if dir == "" {
		dir = "keys"
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Fatal(err)
	}
	path := filepath.Join(dir, kid+".pub")
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(pub)), 0o644); err != nil {
		log.Fatal(err)
	}

	fmt.Println("public key written to", path)
	fmt.Println("issuer env (keep the private key secret):")
	fmt.Printf("export JWT_KID=%s\nexport JWT_PRIVATE_KEY=%s\n", kid, base64.StdEncoding.EncodeToString(priv))
}
