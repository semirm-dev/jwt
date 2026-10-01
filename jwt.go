package jwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	jwtLib "github.com/golang-jwt/jwt/v5"
)

const leeway = 30 * time.Second

var (
	ErrExpired = errors.New("token expired")
	ErrInvalid = errors.New("invalid token")
)

type Config struct {
	Issuer   string
	Audience string
	TTL      time.Duration // token lifetime, e.g. 15 * time.Minute
}

// Claims holds the registered claims set by Signer plus optional custom Data.
type Claims struct {
	jwtLib.RegisteredClaims
	Data map[string]any `json:"data,omitempty"`
}

// Signer issues EdDSA signed tokens. Keep the private key to the issuing service only.
type Signer struct {
	kid string
	key ed25519.PrivateKey
	cfg Config
}

func NewSigner(kid string, key ed25519.PrivateKey, cfg Config) (*Signer, error) {
	if kid == "" || len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("kid and a valid ed25519 private key are required")
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return &Signer{kid: kid, key: key, cfg: cfg}, nil
}

// Sign returns a token for the subject. exp, nbf, iat, iss, aud and jti are always set by the signer.
func (s *Signer) Sign(subject string, data map[string]any) (string, error) {
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}

	now := time.Now()
	token := jwtLib.NewWithClaims(jwtLib.SigningMethodEdDSA, Claims{
		Issuer:    s.cfg.Issuer,
		Subject:   subject,
		Audience:  jwtLib.ClaimStrings{s.cfg.Audience},
		ExpiresAt: jwtLib.NewNumericDate(now.Add(s.cfg.TTL)),
		NotBefore: jwtLib.NewNumericDate(now),
		IssuedAt:  jwtLib.NewNumericDate(now),
		ID:        hex.EncodeToString(jti),
		Data:      data,
	})
	token.Header["kid"] = s.kid

	return token.SignedString(s.key)
}

// Verifier validates tokens using public keys selected by kid. Several keys allow key rotation.
type Verifier struct {
	keys map[string]ed25519.PublicKey
	cfg  Config
}

func NewVerifier(keys map[string]ed25519.PublicKey, cfg Config) (*Verifier, error) {
	if len(keys) == 0 {
		return nil, errors.New("at least one public key is required")
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return &Verifier{keys: keys, cfg: cfg}, nil
}

// Verify checks signature, algorithm, kid, exp, nbf, iat, iss and aud.
// Returned error wraps ErrExpired or ErrInvalid.
func (v *Verifier) Verify(token string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwtLib.ParseWithClaims(token, claims, v.key,
		jwtLib.WithValidMethods([]string{jwtLib.SigningMethodEdDSA.Alg()}),
		jwtLib.WithIssuer(v.cfg.Issuer),
		jwtLib.WithAudience(v.cfg.Audience),
		jwtLib.WithExpirationRequired(),
		jwtLib.WithIssuedAt(),
		jwtLib.WithLeeway(leeway),
	)
	if errors.Is(err, jwtLib.ErrTokenExpired) {
		return nil, fmt.Errorf("%w: %v", ErrExpired, err)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}

	return claims, nil
}

func (v *Verifier) key(t *jwtLib.Token) (any, error) {
	kid, _ := t.Header["kid"].(string)
	key, ok := v.keys[kid]
	if !ok {
		return nil, errors.New("unknown kid")
	}

	return key, nil
}

func (c Config) validate() error {
	if c.Issuer == "" || c.Audience == "" || c.TTL <= 0 {
		return errors.New("issuer, audience and positive ttl are required")
	}

	return nil
}
