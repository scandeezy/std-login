package auth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	stdloginv1 "github.com/scandeezy/std-login/gen/stdlogin/v1"
	"github.com/scandeezy/std-login/gen/stdlogin/v1/stdloginv1connect"
	"github.com/scandeezy/std-login/internal/auth"
	"github.com/scandeezy/std-login/internal/password"
	"github.com/scandeezy/std-login/internal/ratelimit"
	"github.com/scandeezy/std-login/internal/server"
	"github.com/scandeezy/std-login/internal/store/memory"
	"github.com/scandeezy/std-login/internal/token"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.t = c.t.Add(d) }

// outbox captures login links.
type outbox struct {
	ch chan string
}

func (o *outbox) SendLoginLink(_ context.Context, to, link string, _ time.Time) error {
	o.ch <- link
	return nil
}

// next returns the token from the next sent link.
func (o *outbox) next(t *testing.T) string {
	t.Helper()
	select {
	case link := <-o.ch:
		u, _ := url.Parse(link)
		return u.Query().Get("token")
	case <-time.After(2 * time.Second):
		t.Fatal("no login link sent")
		return ""
	}
}

func (o *outbox) none(t *testing.T) {
	t.Helper()
	select {
	case link := <-o.ch:
		t.Fatalf("unexpected login link sent: %s", link)
	case <-time.After(50 * time.Millisecond):
	}
}

type harness struct {
	client stdloginv1connect.AuthServiceClient
	clock  *clock
	mail   *outbox
	issuer *token.Issuer
}

func newHarness(t *testing.T, mod func(*auth.Config)) *harness {
	t.Helper()
	clk := &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	ob := &outbox{ch: make(chan string, 10)}
	iss := token.NewIssuer(token.GenerateKey(), "test", []string{"app"}, 15*time.Minute)
	cfg := auth.Config{
		Store:           memory.New(),
		Hasher:          password.NewHasher(password.Params{Memory: 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}),
		Issuer:          iss,
		Mailer:          ob,
		RefreshTTL:      24 * time.Hour,
		LoginTokenTTL:   10 * time.Minute,
		LoginLinkURL:    "https://app.example.com/login",
		AllowSignup:     true,
		MaxFailedLogins: 3,
		LockoutDuration: 15 * time.Minute,
		ReauthWindow:    10 * time.Minute,
		Now:             clk.Now,
	}
	if mod != nil {
		mod(&cfg)
	}
	srv := httptest.NewServer(server.Handler(auth.New(cfg), iss))
	t.Cleanup(srv.Close)
	return &harness{
		client: stdloginv1connect.NewAuthServiceClient(srv.Client(), srv.URL),
		clock:  clk,
		mail:   ob,
		issuer: iss,
	}
}

func wantCode(t *testing.T, err error, code connect.Code) {
	t.Helper()
	var ce *connect.Error
	if !errors.As(err, &ce) || ce.Code() != code {
		t.Fatalf("got error %v, want code %v", err, code)
	}
}

func (h *harness) emailLogin(t *testing.T, email string) *stdloginv1.TokenPair {
	t.Helper()
	ctx := context.Background()
	if _, err := h.client.StartEmailLogin(ctx, connect.NewRequest(&stdloginv1.StartEmailLoginRequest{Email: email})); err != nil {
		t.Fatal(err)
	}
	resp, err := h.client.CompleteEmailLogin(ctx, connect.NewRequest(&stdloginv1.CompleteEmailLoginRequest{LoginToken: h.mail.next(t)}))
	if err != nil {
		t.Fatal(err)
	}
	return resp.Msg.Tokens
}

func (h *harness) setPassword(t *testing.T, access, pw string) (*stdloginv1.TokenPair, error) {
	req := connect.NewRequest(&stdloginv1.SetPasswordRequest{NewPassword: pw})
	req.Header().Set("Authorization", "Bearer "+access)
	resp, err := h.client.SetPassword(context.Background(), req)
	if err != nil {
		return nil, err
	}
	return resp.Msg.Tokens, nil
}

func (h *harness) passwordLogin(email, pw string) (*stdloginv1.TokenPair, error) {
	resp, err := h.client.LoginWithPassword(context.Background(), connect.NewRequest(&stdloginv1.LoginWithPasswordRequest{Email: email, Password: pw}))
	if err != nil {
		return nil, err
	}
	return resp.Msg.Tokens, nil
}

func (h *harness) refresh(rt string) (*stdloginv1.TokenPair, error) {
	resp, err := h.client.RefreshSession(context.Background(), connect.NewRequest(&stdloginv1.RefreshSessionRequest{RefreshToken: rt}))
	if err != nil {
		return nil, err
	}
	return resp.Msg.Tokens, nil
}

func TestEmailLoginCreatesUserAndIssuesJWT(t *testing.T) {
	h := newHarness(t, nil)
	tp := h.emailLogin(t, "  Alice@Example.com ")

	claims, err := h.issuer.Verify(tp.AccessToken, h.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if claims.Email != "alice@example.com" || claims.Subject != tp.UserId || claims.AMR[0] != auth.MethodEmail {
		t.Errorf("claims = %+v", claims)
	}
	if tp.TokenType != "Bearer" || tp.RefreshToken == "" {
		t.Errorf("token pair = %+v", tp)
	}

	// Same address (normalized) maps to the same user.
	if tp2 := h.emailLogin(t, "alice@example.com"); tp2.UserId != tp.UserId {
		t.Errorf("second login user %s, want %s", tp2.UserId, tp.UserId)
	}
}

func TestLoginTokenSingleUseAndExpiry(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	complete := func(tok string) error {
		_, err := h.client.CompleteEmailLogin(ctx, connect.NewRequest(&stdloginv1.CompleteEmailLoginRequest{LoginToken: tok}))
		return err
	}

	h.client.StartEmailLogin(ctx, connect.NewRequest(&stdloginv1.StartEmailLoginRequest{Email: "a@example.com"}))
	tok := h.mail.next(t)
	if err := complete(tok); err != nil {
		t.Fatal(err)
	}
	wantCode(t, complete(tok), connect.CodeUnauthenticated)

	h.client.StartEmailLogin(ctx, connect.NewRequest(&stdloginv1.StartEmailLoginRequest{Email: "a@example.com"}))
	tok = h.mail.next(t)
	h.clock.Add(10 * time.Minute)
	wantCode(t, complete(tok), connect.CodeUnauthenticated)

	wantCode(t, complete("bogus"), connect.CodeUnauthenticated)
}

func TestSignupDisabled(t *testing.T) {
	h := newHarness(t, func(c *auth.Config) { c.AllowSignup = false })
	_, err := h.client.StartEmailLogin(context.Background(), connect.NewRequest(&stdloginv1.StartEmailLoginRequest{Email: "new@example.com"}))
	if err != nil {
		t.Fatalf("StartEmailLogin must succeed for unknown address, got %v", err)
	}
	h.mail.none(t)
}

func TestInvalidEmail(t *testing.T) {
	h := newHarness(t, nil)
	for _, e := range []string{"", "nope", "Bob <bob@example.com>", "a@b@c"} {
		_, err := h.client.StartEmailLogin(context.Background(), connect.NewRequest(&stdloginv1.StartEmailLoginRequest{Email: e}))
		wantCode(t, err, connect.CodeInvalidArgument)
	}
}

func TestPasswordFlow(t *testing.T) {
	h := newHarness(t, nil)
	tp := h.emailLogin(t, "a@example.com")

	// No password yet.
	_, err := h.passwordLogin("a@example.com", "correct horse battery")
	wantCode(t, err, connect.CodeUnauthenticated)

	_, err = h.setPassword(t, tp.AccessToken, "short")
	wantCode(t, err, connect.CodeInvalidArgument)

	newTP, err := h.setPassword(t, tp.AccessToken, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	// Setting a password revokes the session it was set from...
	_, err = h.refresh(tp.RefreshToken)
	wantCode(t, err, connect.CodeUnauthenticated)
	// ...but the returned replacement session works.
	if _, err := h.refresh(newTP.RefreshToken); err != nil {
		t.Fatalf("refresh replacement session: %v", err)
	}

	got, err := h.passwordLogin("A@example.com", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	claims, _ := h.issuer.Verify(got.AccessToken, h.clock.Now())
	if claims.AMR[0] != auth.MethodPassword || got.UserId != tp.UserId {
		t.Errorf("claims = %+v", claims)
	}

	_, err = h.passwordLogin("a@example.com", "wrong horse battery")
	wantCode(t, err, connect.CodeUnauthenticated)
	_, err = h.passwordLogin("nobody@example.com", "correct horse battery")
	wantCode(t, err, connect.CodeUnauthenticated)
}

func TestSetPasswordRequiresRecentLogin(t *testing.T) {
	h := newHarness(t, nil)
	tp := h.emailLogin(t, "a@example.com")

	_, err := h.setPassword(t, "not-a-jwt", "correct horse battery")
	wantCode(t, err, connect.CodeUnauthenticated)

	// Refreshing keeps the original auth_time, so a refreshed token past the
	// window can't be used to set a password.
	h.clock.Add(11 * time.Minute)
	tp, err = h.refresh(tp.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.setPassword(t, tp.AccessToken, "correct horse battery")
	wantCode(t, err, connect.CodePermissionDenied)
}

func TestLockout(t *testing.T) {
	h := newHarness(t, nil)
	tp := h.emailLogin(t, "a@example.com")
	if _, err := h.setPassword(t, tp.AccessToken, "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		_, err := h.passwordLogin("a@example.com", "wrong password!!")
		wantCode(t, err, connect.CodeUnauthenticated)
	}
	// Locked: even the right password fails, indistinguishably.
	_, err := h.passwordLogin("a@example.com", "correct horse battery")
	wantCode(t, err, connect.CodeUnauthenticated)

	h.clock.Add(15 * time.Minute)
	if _, err := h.passwordLogin("a@example.com", "correct horse battery"); err != nil {
		t.Fatalf("login after lockout expired: %v", err)
	}
}

func TestRefreshRotationAndReuseDetection(t *testing.T) {
	h := newHarness(t, nil)
	tp1 := h.emailLogin(t, "a@example.com")

	tp2, err := h.refresh(tp1.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if tp2.RefreshToken == tp1.RefreshToken {
		t.Fatal("refresh token not rotated")
	}
	// Replaying the old token revokes the session, including tp2.
	_, err = h.refresh(tp1.RefreshToken)
	wantCode(t, err, connect.CodeUnauthenticated)
	_, err = h.refresh(tp2.RefreshToken)
	wantCode(t, err, connect.CodeUnauthenticated)
}

func TestRefreshExpiry(t *testing.T) {
	h := newHarness(t, nil)
	tp := h.emailLogin(t, "a@example.com")
	h.clock.Add(24 * time.Hour)
	_, err := h.refresh(tp.RefreshToken)
	wantCode(t, err, connect.CodeUnauthenticated)
}

func TestLogout(t *testing.T) {
	h := newHarness(t, nil)
	tp := h.emailLogin(t, "a@example.com")
	other := h.emailLogin(t, "a@example.com")
	ctx := context.Background()

	if _, err := h.client.Logout(ctx, connect.NewRequest(&stdloginv1.LogoutRequest{RefreshToken: tp.RefreshToken})); err != nil {
		t.Fatal(err)
	}
	_, err := h.refresh(tp.RefreshToken)
	wantCode(t, err, connect.CodeUnauthenticated)
	// Other sessions are unaffected.
	if _, err := h.refresh(other.RefreshToken); err != nil {
		t.Fatalf("other session: %v", err)
	}
	// Idempotent / unknown tokens are fine.
	if _, err := h.client.Logout(ctx, connect.NewRequest(&stdloginv1.LogoutRequest{RefreshToken: "bogus"})); err != nil {
		t.Fatal(err)
	}
}

func TestRateLimits(t *testing.T) {
	h := newHarness(t, func(c *auth.Config) {
		c.IPLimiter = ratelimit.NewMemory(3, time.Minute)
		c.EmailLimiter = ratelimit.NewMemory(1, time.Hour)
	})
	ctx := context.Background()
	start := func(email string) error {
		_, err := h.client.StartEmailLogin(ctx, connect.NewRequest(&stdloginv1.StartEmailLoginRequest{Email: email}))
		return err
	}
	if err := start("a@example.com"); err != nil {
		t.Fatal(err)
	}
	h.mail.next(t)
	// Per-address limit: silent success, no mail.
	if err := start("a@example.com"); err != nil {
		t.Fatal(err)
	}
	h.mail.none(t)
	// Per-IP limit: explicit error.
	start("b@example.com")
	wantCode(t, start("c@example.com"), connect.CodeResourceExhausted)
}

type brokenLimiter struct{}

func (brokenLimiter) Allow(context.Context, string, time.Time) (bool, error) {
	return false, errors.New("redis: connection refused")
}

func TestRateLimiterErrorsFailOpen(t *testing.T) {
	h := newHarness(t, func(c *auth.Config) {
		c.IPLimiter = brokenLimiter{}
		c.EmailLimiter = brokenLimiter{}
	})
	h.emailLogin(t, "a@example.com") // exercises both limiters
}

func TestJWKSEndpoint(t *testing.T) {
	iss := token.NewIssuer(token.GenerateKey(), "test", nil, time.Minute)
	srv := httptest.NewServer(server.Handler(auth.New(auth.Config{Issuer: iss}), iss))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/json" {
		t.Errorf("status %d, content-type %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
}
