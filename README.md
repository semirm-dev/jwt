![Go](https://img.shields.io/github/go-mod/go-version/semirm-dev/jwt)

Small EdDSA (Ed25519) JWT library with safe defaults.

- `exp`, `nbf`, `iat`, `iss`, `aud`, `jti` always set by the signer and required by the verifier
- only `EdDSA` accepted (no `none`, no HMAC/algorithm confusion)
- `kid` header + multiple verifier keys for key rotation
- verifiers need only public keys, they cannot mint tokens

```go
pub, priv, _ := ed25519.GenerateKey(rand.Reader) // load from your secret manager in production
cfg := jwt.Config{Issuer: "auth", Audience: "api", TTL: 15 * time.Minute}

signer, _ := jwt.NewSigner("key-2024-01", priv, cfg)
token, _ := signer.Sign("user-1", map[string]any{"role": "admin"})

verifier, _ := jwt.NewVerifier(map[string]ed25519.PublicKey{"key-2024-01": pub}, cfg)
claims, err := verifier.Verify(token) // errors.Is(err, jwt.ErrExpired / jwt.ErrInvalid)
```

### Key IDs (`kid`) and rotation

`kid` is a non-secret label in the token header naming the key that signed it. The verifier uses it to pick the public key. Use any unique string (e.g. `2026-10`) and never reuse one for a different key.

| Service  | Holds                                        |
|----------|----------------------------------------------|
| Issuer   | current private key + its kid (secret manager, never in the repo) |
| Verifier | map of kid -> public key for every key still valid (not secret)   |

```go
verifier, _ := jwt.NewVerifier(map[string]ed25519.PublicKey{
    "2026-10": currentPub,
    "2026-01": previousPub, // keep until tokens signed with it expire
}, cfg)
```

Rotate every 3-12 months, in this order:
1. Generate a new key pair and kid.
2. Deploy the new public key to all verifiers, next to the old one.
3. Switch the issuer to the new private key and kid.
4. After at least one `TTL`, remove the old public key and delete the old private key.

Do not switch the issuer before every verifier knows the new key. If a private key leaks, skip the grace period and drop its public key immediately (users must sign in again).

Keys are read at construction. To rotate without a restart, build a new `Verifier` and swap it in (e.g. `atomic.Pointer[jwt.Verifier]`), or just redeploy.

Send tokens over TLS only, keep access TTLs short, and keep PII out of `Data`.

### Examples
Runnable key generation, issuer and verifier (with hot key reload) in [examples/](examples/):
```shell
go run ./examples/keygen 2026-01      # writes keys/2026-01.pub, prints JWT_KID / JWT_PRIVATE_KEY exports
export JWT_KID=... JWT_PRIVATE_KEY=...
go run ./examples/issuer              # :8081  POST /login?user=user-1
go run ./examples/verifier            # :8080  GET /me  (Authorization: Bearer <token>)
```
To rotate: `go run ./examples/keygen 2026-10`, wait ~5s for the verifier to reload, restart the issuer with the new exports, and delete the old `keys/*.pub` after one TTL.

### Run tests
```shell
make test-cover
```
