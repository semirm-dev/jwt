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

Rotation: add the new public key to verifiers, switch the signer to the new key/kid, remove the old public key after `TTL` has passed.

Send tokens over TLS only, keep access TTLs short, and keep PII out of `Data`.

### Run tests
```shell
make test-cover
```
