package jwt_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/semirm-dev/jwt"
	jwtLib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var cfg = jwt.Config{Issuer: "auth", Audience: "api", TTL: time.Minute}

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return pub, priv
}

func setup(t *testing.T) (*jwt.Signer, *jwt.Verifier, ed25519.PrivateKey) {
	pub, priv := newKey(t)
	s, err := jwt.NewSigner("k1", priv, cfg)
	require.NoError(t, err)
	v, err := jwt.NewVerifier(map[string]ed25519.PublicKey{"k1": pub}, cfg)
	require.NoError(t, err)
	return s, v, priv
}

// forge signs arbitrary claims, bypassing Signer.
func forge(t *testing.T, method jwtLib.SigningMethod, kid string, key any, c jwtLib.RegisteredClaims) string {
	tok := jwtLib.NewWithClaims(method, c)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(key)
	require.NoError(t, err)
	return signed
}

func validClaims() jwtLib.RegisteredClaims {
	return jwtLib.RegisteredClaims{
		Issuer:    "auth",
		Audience:  jwtLib.ClaimStrings{"api"},
		ExpiresAt: jwtLib.NewNumericDate(time.Now().Add(time.Minute)),
	}
}

func TestSignVerify(t *testing.T) {
	s, v, _ := setup(t)

	token, err := s.Sign("user-1", map[string]any{"role": "admin"})
	require.NoError(t, err)

	claims, err := v.Verify(token)
	require.NoError(t, err)
	assert.Equal(t, "user-1", claims.Subject)
	assert.Equal(t, "admin", claims.Data["role"])
	assert.Equal(t, "auth", claims.Issuer)
	assert.NotEmpty(t, claims.ID)
	assert.NotNil(t, claims.ExpiresAt)
	assert.NotNil(t, claims.NotBefore)
	assert.NotNil(t, claims.IssuedAt)
}

func TestSign_UniqueJTI(t *testing.T) {
	s, v, _ := setup(t)

	a, _ := s.Sign("u", nil)
	b, _ := s.Sign("u", nil)
	ca, err := v.Verify(a)
	require.NoError(t, err)
	cb, err := v.Verify(b)
	require.NoError(t, err)
	assert.NotEqual(t, ca.ID, cb.ID)
}

func TestVerify_Expired(t *testing.T) {
	_, v, priv := setup(t)
	c := validClaims()
	c.ExpiresAt = jwtLib.NewNumericDate(time.Now().Add(-time.Hour))

	_, err := v.Verify(forge(t, jwtLib.SigningMethodEdDSA, "k1", priv, c))
	assert.ErrorIs(t, err, jwt.ErrExpired)
}

func TestVerify_Invalid(t *testing.T) {
	_, v, priv := setup(t)
	pub, otherPriv := newKey(t)

	noExp := validClaims()
	noExp.ExpiresAt = nil
	wrongIss := validClaims()
	wrongIss.Issuer = "evil"
	wrongAud := validClaims()
	wrongAud.Audience = jwtLib.ClaimStrings{"other"}
	notYet := validClaims()
	notYet.NotBefore = jwtLib.NewNumericDate(time.Now().Add(time.Hour))

	hmacKey := []byte(pub) // algorithm confusion: HMAC keyed with the public key
	cases := map[string]string{
		"missing exp":     forge(t, jwtLib.SigningMethodEdDSA, "k1", priv, noExp),
		"wrong issuer":    forge(t, jwtLib.SigningMethodEdDSA, "k1", priv, wrongIss),
		"wrong audience":  forge(t, jwtLib.SigningMethodEdDSA, "k1", priv, wrongAud),
		"not yet valid":   forge(t, jwtLib.SigningMethodEdDSA, "k1", priv, notYet),
		"unknown kid":     forge(t, jwtLib.SigningMethodEdDSA, "k2", priv, validClaims()),
		"missing kid":     forge(t, jwtLib.SigningMethodEdDSA, "", priv, validClaims()),
		"wrong signature": forge(t, jwtLib.SigningMethodEdDSA, "k1", otherPriv, validClaims()),
		"alg none":        forge(t, jwtLib.SigningMethodNone, "k1", jwtLib.UnsafeAllowNoneSignatureType, validClaims()),
		"hmac confusion":  forge(t, jwtLib.SigningMethodHS256, "k1", hmacKey, validClaims()),
		"garbage":         "not-a-jwt",
		"empty":           "",
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			claims, err := v.Verify(token)
			assert.ErrorIs(t, err, jwt.ErrInvalid)
			assert.Nil(t, claims)
		})
	}
}

func TestVerify_KeyRotation(t *testing.T) {
	oldPub, oldPriv := newKey(t)
	newPub, newPriv := newKey(t)
	oldSigner, _ := jwt.NewSigner("old", oldPriv, cfg)
	newSigner, _ := jwt.NewSigner("new", newPriv, cfg)
	v, err := jwt.NewVerifier(map[string]ed25519.PublicKey{"old": oldPub, "new": newPub}, cfg)
	require.NoError(t, err)

	for _, s := range []*jwt.Signer{oldSigner, newSigner} {
		token, err := s.Sign("u", nil)
		require.NoError(t, err)
		_, err = v.Verify(token)
		assert.NoError(t, err)
	}
}

func TestConstructors_Validation(t *testing.T) {
	pub, priv := newKey(t)
	keys := map[string]ed25519.PublicKey{"k1": pub}

	_, err := jwt.NewSigner("", priv, cfg)
	assert.Error(t, err)
	_, err = jwt.NewSigner("k1", ed25519.PrivateKey("short"), cfg)
	assert.Error(t, err)
	_, err = jwt.NewSigner("k1", priv, jwt.Config{Issuer: "a", Audience: "b"})
	assert.Error(t, err)
	_, err = jwt.NewVerifier(nil, cfg)
	assert.Error(t, err)
	_, err = jwt.NewVerifier(keys, jwt.Config{TTL: time.Minute})
	assert.Error(t, err)
}

func TestSign_EmptySubject(t *testing.T) {
	s, _, _ := setup(t)

	token, err := s.Sign("", nil)
	assert.Error(t, err)
	assert.Empty(t, token)
}

func TestNewVerifier_CopiesKeys(t *testing.T) {
	pub, priv := newKey(t)
	keys := map[string]ed25519.PublicKey{"k1": pub}
	s, _ := jwt.NewSigner("k1", priv, cfg)
	v, err := jwt.NewVerifier(keys, cfg)
	require.NoError(t, err)

	delete(keys, "k1")

	token, _ := s.Sign("u", nil)
	_, err = v.Verify(token)
	assert.NoError(t, err)
}
