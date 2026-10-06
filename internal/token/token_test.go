package token

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIssueVerify(t *testing.T) {
	iss := NewIssuer(GenerateKey(), "https://login.example.com", []string{"app"}, 15*time.Minute)
	now := time.Now()
	sub := Subject{UserID: "u1", Email: "a@example.com", SessionID: "s1", AuthTime: now, AuthMethod: "pwd"}
	raw, exp, err := iss.Issue(sub, now)
	if err != nil {
		t.Fatal(err)
	}
	if !exp.Equal(now.Add(15 * time.Minute)) {
		t.Errorf("exp = %v", exp)
	}
	c, err := iss.Verify(raw, now)
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != "u1" || c.SessionID != "s1" || c.AMR[0] != "pwd" || c.Email != "a@example.com" {
		t.Errorf("claims = %+v", c)
	}
	if _, err := iss.Verify(raw, now.Add(16*time.Minute)); err == nil {
		t.Error("expired token verified")
	}
	other := NewIssuer(GenerateKey(), "https://login.example.com", []string{"app"}, time.Minute)
	if _, err := other.Verify(raw, now); err == nil {
		t.Error("token verified with wrong key")
	}
	wrongAud := NewIssuer(iss.key, "https://login.example.com", []string{"other"}, time.Minute)
	if _, err := wrongAud.Verify(raw, now); err == nil {
		t.Error("token verified with wrong audience")
	}
}

func TestJWKS(t *testing.T) {
	iss := NewIssuer(GenerateKey(), "i", nil, time.Minute)
	var doc struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(iss.JWKS(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Keys) != 1 || doc.Keys[0]["kid"] != iss.kid || doc.Keys[0]["crv"] != "Ed25519" {
		t.Errorf("jwks = %+v", doc)
	}
}

func TestKeyPEMRoundTrip(t *testing.T) {
	k := GenerateKey()
	b, err := EncodeKeyPEM(k)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "key.pem")
	os.WriteFile(path, b, 0o600)
	got, err := LoadKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(k) {
		t.Error("key mismatch")
	}
}

func TestOpaque(t *testing.T) {
	tok, hash := NewOpaque()
	if len(tok) != 43 || Hash(tok) != hash {
		t.Errorf("tok=%q hash=%q", tok, hash)
	}
	tok2, _ := NewOpaque()
	if tok == tok2 {
		t.Error("tokens repeat")
	}
}
