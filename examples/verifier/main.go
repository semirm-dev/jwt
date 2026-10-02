// Verifier service with hot key reload. GET /me with "Authorization: Bearer <token>".
// Public keys are read from $KEYS_DIR/<kid>.pub (default "keys") every 5 seconds,
// so rotating means adding/removing files, no restart.
// Usage: go run ./examples/verifier
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/semirm-dev/jwt"
)

var cfg = jwt.Config{Issuer: "auth", Audience: "api", TTL: 15 * time.Minute}

func loadVerifier(dir string) (*jwt.Verifier, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.pub"))
	if err != nil {
		return nil, err
	}

	keys := map[string]ed25519.PublicKey{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
		if err != nil {
			return nil, err
		}
		keys[strings.TrimSuffix(filepath.Base(f), ".pub")] = ed25519.PublicKey(raw)
	}

	return jwt.NewVerifier(keys, cfg)
}

func main() {
	dir := os.Getenv("KEYS_DIR")
	if dir == "" {
		dir = "keys"
	}

	var current atomic.Pointer[jwt.Verifier]
	v, err := loadVerifier(dir)
	if err != nil {
		log.Fatal(err)
	}
	current.Store(v)

	go func() {
		for range time.Tick(5 * time.Second) {
			if v, err := loadVerifier(dir); err != nil {
				log.Println("key reload failed, keeping previous keys:", err)
			} else {
				current.Store(v)
			}
		}
	}()

	http.HandleFunc("GET /me", func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		claims, err := current.Load().Verify(token)
		if err != nil {
			log.Println("verify failed:", err)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		fmt.Fprintf(w, "hello %s (role=%v)\n", claims.Subject, claims.Data["role"])
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
