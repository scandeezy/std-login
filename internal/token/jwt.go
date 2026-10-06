// Package token issues and verifies the service's tokens: EdDSA-signed JWT
// access tokens and opaque random tokens for login links and refresh.
package token

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims are the access token claims. Downstream services should verify the
// signature (via JWKS), "iss", "aud" and "exp", and use "sub" as the user ID.
type Claims struct {
	jwt.RegisteredClaims
	Email     string   `json:"email"`
	SessionID string   `json:"sid"`
	AuthTime  int64    `json:"auth_time"` // unix seconds of the actual login
	AMR       []string `json:"amr"`       // "pwd" or "email"
}

// Issuer signs and verifies access tokens.
type Issuer struct {
	key      ed25519.PrivateKey
	kid      string
	issuer   string
	audience []string
	ttl      time.Duration
}

func NewIssuer(key ed25519.PrivateKey, issuer string, audience []string, ttl time.Duration) *Issuer {
	pub := key.Public().(ed25519.PublicKey)
	sum := sha256.Sum256(pub)
	return &Issuer{
		key:      key,
		kid:      base64.RawURLEncoding.EncodeToString(sum[:8]),
		issuer:   issuer,
		audience: audience,
		ttl:      ttl,
	}
}

// Subject is the authenticated identity an access token is issued for.
type Subject struct {
	UserID     string
	Email      string
	SessionID  string
	AuthTime   time.Time
	AuthMethod string
}

// Issue returns a signed access token and its expiry.
func (i *Issuer) Issue(s Subject, now time.Time) (string, time.Time, error) {
	exp := now.Add(i.ttl)
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.issuer,
			Subject:   s.UserID,
			Audience:  i.audience,
			ExpiresAt: jwt.NewNumericDate(exp),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        NewID(),
		},
		Email:     s.Email,
		SessionID: s.SessionID,
		AuthTime:  s.AuthTime.Unix(),
		AMR:       []string{s.AuthMethod},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	t.Header["kid"] = i.kid
	signed, err := t.SignedString(i.key)
	return signed, exp, err
}

// Verify parses and validates an access token issued by this Issuer.
func (i *Issuer) Verify(raw string, now time.Time) (*Claims, error) {
	opts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		jwt.WithIssuer(i.issuer),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(func() time.Time { return now }),
	}
	if len(i.audience) > 0 {
		opts = append(opts, jwt.WithAudience(i.audience[0]))
	}
	var c Claims
	_, err := jwt.ParseWithClaims(raw, &c, func(*jwt.Token) (any, error) {
		return i.key.Public(), nil
	}, opts...)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// JWKS returns the JSON Web Key Set document for the signing key.
func (i *Issuer) JWKS() []byte {
	pub := i.key.Public().(ed25519.PublicKey)
	doc := map[string]any{"keys": []map[string]string{{
		"kty": "OKP",
		"crv": "Ed25519",
		"use": "sig",
		"alg": "EdDSA",
		"kid": i.kid,
		"x":   base64.RawURLEncoding.EncodeToString(pub),
	}}}
	b, _ := json.Marshal(doc)
	return b
}

// GenerateKey returns a new Ed25519 private key.
func GenerateKey() ed25519.PrivateKey {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	return priv
}

// EncodeKeyPEM encodes a private key as a PKCS#8 PEM block.
func EncodeKeyPEM(key ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// LoadKeyFile reads a PKCS#8 PEM Ed25519 private key.
func LoadKeyFile(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is %T, want ed25519", k)
	}
	return ek, nil
}
