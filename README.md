![Go](https://img.shields.io/github/go-mod/go-version/semirm-dev/jwt)

Small EdDSA (Ed25519) JWT library with safe defaults.

What it does for you:

- The signer always sets `exp`, `nbf`, `iat`, `iss`, `aud`, `sub` and `jti`, and the verifier rejects tokens missing any of them.
- Only `EdDSA` is accepted, so no `none` tokens and no HMAC/RSA mix-ups.
- Tokens carry a `kid` header and the verifier can hold several keys, so you can rotate keys.
- Verifiers only need public keys. They can check tokens but can't create them.

## Usage

```go
pub, priv, _ := ed25519.GenerateKey(rand.Reader) // in production, load this from your secret manager
cfg := jwt.Config{Issuer: "auth", Audience: "api", TTL: 15 * time.Minute}

signer, _ := jwt.NewSigner("key-2024-01", priv, cfg)
token, _ := signer.Sign("user-1", map[string]any{"role": "admin"})

verifier, _ := jwt.NewVerifier(map[string]ed25519.PublicKey{"key-2024-01": pub}, cfg)
claims, err := verifier.Verify(token) // check with errors.Is(err, jwt.ErrExpired) or jwt.ErrInvalid
```

## Key rotation

`kid` is just a name for the key that signed the token. It isn't secret. Pick something unique like `2026-10` and don't reuse it for a different key.

The issuer keeps the current private key and its kid (in a secret manager, not in the repo). Verifiers keep a map of kid to public key for every key that's still in use:

```go
verifier, _ := jwt.NewVerifier(map[string]ed25519.PublicKey{
    "2026-10": currentPub,
    "2026-01": previousPub, // keep it until tokens signed with it have expired
}, cfg)
```

I'd rotate every few months. Order matters:

1. Make a new key pair and kid.
2. Give the new public key to every verifier, next to the old one.
3. Switch the issuer to the new private key.
4. Wait at least one `TTL`, then remove the old public key and delete the old private key.

If you switch the issuer before all verifiers have the new key, they'll reject the new tokens. If a private key leaks, don't wait: drop its public key right away (everyone has to log in again).

Keys are only read when you create the `Verifier`. To pick up new keys without restarting, build a new one and swap it in (an `atomic.Pointer[jwt.Verifier]` works), or just redeploy.

Also: use TLS, keep access token TTLs short, and don't put personal data in `Data`.

## Examples

[examples/](examples/) has a key generator, an issuer and a verifier that reloads keys on its own:

```shell
go run ./examples/keygen 2026-01      # writes keys/2026-01.pub, prints JWT_KID / JWT_PRIVATE_KEY exports
export JWT_KID=... JWT_PRIVATE_KEY=...
go run ./examples/issuer              # :8081  POST /login?user=user-1
go run ./examples/verifier            # :8080  GET /me  (Authorization: Bearer <token>)
```

To try rotation, run `go run ./examples/keygen 2026-10`, wait about 5 seconds for the verifier to notice, restart the issuer with the new exports, and delete the old `keys/*.pub` once a TTL has passed.

## Tests

```shell
make test-cover
```
