package password

import (
	"strings"
	"testing"
)

var testParams = Params{Memory: 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}

func TestHashVerify(t *testing.T) {
	h := NewHasher(testParams)
	enc, err := h.Hash("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enc, "$argon2id$v=19$m=1024,t=1,p=1$") {
		t.Fatalf("unexpected encoding %q", enc)
	}
	if !h.Verify("correct horse battery", enc) {
		t.Error("correct password rejected")
	}
	if h.Verify("wrong horse battery", enc) {
		t.Error("wrong password accepted")
	}
	if h.Verify("anything", "") {
		t.Error("empty hash accepted")
	}
	if h.Verify("anything", "$argon2id$garbage") {
		t.Error("malformed hash accepted")
	}
}

func TestNeedsRehash(t *testing.T) {
	h := NewHasher(testParams)
	enc, _ := h.Hash("correct horse battery")
	if h.NeedsRehash(enc) {
		t.Error("fresh hash needs rehash")
	}
	stronger := NewHasher(Params{Memory: 2048, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32})
	if !stronger.NeedsRehash(enc) {
		t.Error("weaker hash not flagged for rehash")
	}
	if !stronger.Verify("correct horse battery", enc) {
		t.Error("old-params hash no longer verifies")
	}
}

func TestValidate(t *testing.T) {
	for pw, want := range map[string]error{
		"short":                     ErrTooShort,
		"ünïcödé!!!":                nil, // 10 runes, more bytes
		strings.Repeat("a", 257):    ErrTooLong,
		"long enough password here": nil,
	} {
		if got := Validate(pw); got != want {
			t.Errorf("Validate(%q) = %v, want %v", pw, got, want)
		}
	}
}
