package server_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/scandeezy/std-login/internal/auth"
	"github.com/scandeezy/std-login/internal/server"
	"github.com/scandeezy/std-login/internal/store/memory"
	"github.com/scandeezy/std-login/internal/token"
)

// TestNoCORS locks in that the service does not allow cross-origin browser
// requests. If CORS is ever wanted, it must be a deliberate change (see the
// CORS section of CLAUDE.md), not something added in passing.
func TestNoCORS(t *testing.T) {
	iss := token.NewIssuer(token.GenerateKey(), "test", nil, time.Minute)
	srv := httptest.NewServer(server.Handler(auth.New(auth.Config{Store: memory.New(), Issuer: iss}), iss))
	defer srv.Close()

	const rpc = "/stdlogin.v1.AuthService/Logout"
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

	t.Run("preflight", func(t *testing.T) {
		resp := do(t, http.MethodOptions, rpc, "", "", map[string]string{
			"Access-Control-Request-Method":  "POST",
			"Access-Control-Request-Headers": "content-type,authorization",
		})
		noCORSHeaders(t, resp)
	})

	t.Run("json post", func(t *testing.T) {
		resp := do(t, http.MethodPost, rpc, "application/json", `{"refreshToken":"x"}`, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d", resp.StatusCode)
		}
		noCORSHeaders(t, resp)
	})

	// Requests a browser sends cross-origin without a preflight must not
	// reach an RPC.
	t.Run("simple request rejected", func(t *testing.T) {
		for _, ct := range []string{"text/plain", "application/x-www-form-urlencoded", "multipart/form-data"} {
			resp := do(t, http.MethodPost, rpc, ct, `{"refreshToken":"x"}`, nil)
			if resp.StatusCode != http.StatusUnsupportedMediaType {
				t.Errorf("%s: status %d, want 415", ct, resp.StatusCode)
			}
			noCORSHeaders(t, resp)
		}
	})

	t.Run("jwks", func(t *testing.T) {
		noCORSHeaders(t, do(t, http.MethodGet, "/.well-known/jwks.json", "", "", nil))
	})
}
