// Issuer service. POST /login?user=<id> returns a token.
// Demo only: a real login must authenticate the user first.
// Usage: JWT_KID=... JWT_PRIVATE_KEY=... go run ./examples/issuer
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/semirm-dev/jwt"
)

func main() {
	raw, err := base64.StdEncoding.DecodeString(os.Getenv("JWT_PRIVATE_KEY"))
	if err != nil {
		log.Fatal(err)
	}

	signer, err := jwt.NewSigner(os.Getenv("JWT_KID"), ed25519.PrivateKey(raw), jwt.Config{
		Issuer:   "auth",
		Audience: "api",
		TTL:      15 * time.Minute,
	})
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		token, err := signer.Sign(r.URL.Query().Get("user"), map[string]any{"role": "user"})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		fmt.Fprint(w, token)
	})

	log.Fatal(http.ListenAndServe(":8081", nil))
}
