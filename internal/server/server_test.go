package server_test

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/scandeezy/std-login/internal/auth"
	"github.com/scandeezy/std-login/internal/mail"
	"github.com/scandeezy/std-login/internal/password"
	"github.com/scandeezy/std-login/internal/server"
	"github.com/scandeezy/std-login/internal/store/memory"
	"github.com/scandeezy/std-login/internal/token"
)

// TestNoCORS locks in that the service does not allow cross-origin browser
// requests. If CORS is ever wanted, it must be a deliberate change (see the
// CORS section of CLAUDE.md), not something added in passing.
func TestNoCORS(t *testing.T) {
	iss := token.NewIssuer(token.GenerateKey(), "test", nil, time.Minute)
	h, err := server.Handler(auth.New(auth.Config{Store: memory.New(), Issuer: iss}), iss)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	const origin = "https://evil.example.com"

	do := func(t *testing.T, method, path, contentType, body string, hdr map[string]string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		req.Header.Set("Origin", origin)
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	noCORSHeaders := func(t *testing.T, resp *http.Response) {
		t.Helper()
		for k := range resp.Header {
			if strings.HasPrefix(strings.ToLower(k), "access-control-") {
				t.Errorf("unexpected CORS header %s: %q", k, resp.Header.Get(k))
			}
		}
	}

	// The RPC path is served by Connect directly; the REST path goes through
	// Vanguard. Both must behave the same way.
	for _, path := range []string{"/api.v1.AuthService/Logout", "/api/session/logout"} {
		t.Run(path, func(t *testing.T) {
			t.Run("preflight", func(t *testing.T) {
				resp := do(t, http.MethodOptions, path, "", "", map[string]string{
					"Access-Control-Request-Method":  "POST",
					"Access-Control-Request-Headers": "content-type,authorization",
				})
				noCORSHeaders(t, resp)
			})

			t.Run("json post", func(t *testing.T) {
				resp := do(t, http.MethodPost, path, "application/json", `{"refreshToken":"x"}`, nil)
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("status %d", resp.StatusCode)
				}
				noCORSHeaders(t, resp)
			})

			// Requests a browser sends cross-origin without a preflight must not
			// reach an RPC.
			t.Run("simple request rejected", func(t *testing.T) {
				for _, ct := range []string{"text/plain", "application/x-www-form-urlencoded", "multipart/form-data"} {
					resp := do(t, http.MethodPost, path, ct, `{"refreshToken":"x"}`, nil)
					if resp.StatusCode != http.StatusUnsupportedMediaType {
						t.Errorf("%s: status %d, want 415", ct, resp.StatusCode)
					}
					noCORSHeaders(t, resp)
				}
			})
		})
	}

	t.Run("jwks", func(t *testing.T) {
		noCORSHeaders(t, do(t, http.MethodGet, "/.well-known/jwks.json", "", "", nil))
	})
}

// TestREST checks that the google.api.http routes in auth.proto are served
// and map errors to HTTP status codes.
func TestREST(t *testing.T) {
	iss := token.NewIssuer(token.GenerateKey(), "test", nil, time.Minute)
	h, err := server.Handler(auth.New(auth.Config{
		Store:         memory.New(),
		Hasher:        password.NewHasher(password.Params{Memory: 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}),
		Issuer:        iss,
		Mailer:        mail.LogSender{Logger: slog.New(slog.DiscardHandler)},
		LoginTokenTTL: time.Minute,
		AllowSignup:   true,
		ReauthWindow:  time.Minute,
	}), iss)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	for _, tc := range []struct {
		method, path, body string
		want               int
	}{
		{"POST", "/api/session/pwlogin", `{"email":"a@example.com","password":"wrong-password"}`, http.StatusUnauthorized},
		{"POST", "/api/session/emlogin", `{"email":"a@example.com"}`, http.StatusOK},
		{"POST", "/api/session/emcomplete", `{"loginToken":"bogus"}`, http.StatusUnauthorized},
		{"POST", "/api/session/refresh", `{"refreshToken":"bogus"}`, http.StatusUnauthorized},
		{"POST", "/api/session/logout", `{"refreshToken":"bogus"}`, http.StatusOK},
		{"POST", "/api/session/setpw", `{"newPassword":"correct horse battery staple"}`, http.StatusUnauthorized},
		{"GET", "/api/session/logout", "", http.StatusMethodNotAllowed},
		{"POST", "/api/session/nope", `{}`, http.StatusNotFound},
	} {
		req, _ := http.NewRequest(tc.method, srv.URL+tc.path, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Errorf("%s %s: status %d, want %d", tc.method, tc.path, resp.StatusCode, tc.want)
		}
		if got := resp.Header.Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s %s: Cache-Control %q, want no-store", tc.method, tc.path, got)
		}
	}
}
