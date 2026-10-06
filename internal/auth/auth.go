// Package auth implements stdlogin.v1.AuthService.
//
// Security properties maintained here (keep them when changing this code):
//   - No account enumeration: every password-login failure returns the same
//     error after the same amount of hashing work, and StartEmailLogin always
//     succeeds and sends mail asynchronously.
//   - Passwords can only be attached to accounts whose email was proven via an
//     email login, and setting one requires a recent (non-refreshed) login.
//   - Login and refresh tokens are stored only as SHA-256 hashes and are
//     single use; reusing a refresh token revokes its whole session.
//   - Changing a password invalidates all existing sessions.
package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	stdloginv1 "github.com/scandeezy/std-login/gen/stdlogin/v1"
	"github.com/scandeezy/std-login/gen/stdlogin/v1/stdloginv1connect"
	mailer "github.com/scandeezy/std-login/internal/mail"
	"github.com/scandeezy/std-login/internal/password"
	"github.com/scandeezy/std-login/internal/ratelimit"
	"github.com/scandeezy/std-login/internal/store"
	"github.com/scandeezy/std-login/internal/token"
)

const (
	MethodPassword = "pwd"
	MethodEmail    = "email"
)

type Config struct {
	Store  store.Store
	Hasher *password.Hasher
	Issuer *token.Issuer
	Mailer mailer.Sender
	Logger *slog.Logger

	// IPLimiter throttles unauthenticated RPCs per client IP.
	IPLimiter ratelimit.Limiter
	// EmailLimiter throttles StartEmailLogin per target address.
	EmailLimiter ratelimit.Limiter

	RefreshTTL    time.Duration
	LoginTokenTTL time.Duration
	// LoginLinkURL is the client URL emailed to users; the login token is
	// added as the "token" query parameter.
	LoginLinkURL string
	// AllowSignup creates an account on first successful email login.
	AllowSignup bool

	MaxFailedLogins int
	LockoutDuration time.Duration
	// ReauthWindow is how recent the login behind an access token must be
	// for SetPassword.
	ReauthWindow time.Duration

	// TrustProxyHeaders uses the last X-Forwarded-For entry as the client
	// IP. Enable only behind a proxy that sets it.
	TrustProxyHeaders bool

	// Now overrides the clock (tests).
	Now func() time.Time
}

type Service struct {
	cfg Config
}

var _ stdloginv1connect.AuthServiceHandler = (*Service)(nil)

func New(cfg Config) *Service {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.IPLimiter == nil {
		cfg.IPLimiter = ratelimit.Unlimited{}
	}
	if cfg.EmailLimiter == nil {
		cfg.EmailLimiter = ratelimit.Unlimited{}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Service{cfg: cfg}
}

var (
	errInvalidCredentials = connect.NewError(connect.CodeUnauthenticated, errors.New("invalid credentials"))
	errInvalidToken       = connect.NewError(connect.CodeUnauthenticated, errors.New("invalid or expired token"))
	errRateLimited        = connect.NewError(connect.CodeResourceExhausted, errors.New("too many requests"))
	errInvalidEmail       = connect.NewError(connect.CodeInvalidArgument, errors.New("invalid email address"))
)

// now is truncated to the minimum precision stores guarantee, so values
// compare equal after a round trip.
func (s *Service) now() time.Time {
	return s.cfg.Now().UTC().Truncate(time.Millisecond)
}

func (s *Service) internal(ctx context.Context, msg string, err error) error {
	s.cfg.Logger.ErrorContext(ctx, msg, "err", err)
	return connect.NewError(connect.CodeInternal, errors.New("internal error"))
}

// NormalizeEmail validates a bare address and returns its canonical (trimmed,
// lowercased) form, which is the key accounts are stored under.
func NormalizeEmail(raw string) (string, bool) {
	e := strings.ToLower(strings.TrimSpace(raw))
	if len(e) > 254 {
		return "", false
	}
	a, err := mail.ParseAddress(e)
	if err != nil || a.Address != e || a.Name != "" {
		return "", false
	}
	return e, true
}

func (s *Service) clientIP(h interface{ Get(string) string }, peer string) string {
	if s.cfg.TrustProxyHeaders {
		if xff := h.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}
	if host, _, err := net.SplitHostPort(peer); err == nil {
		return host
	}
	return peer
}

func (s *Service) allowIP(req connect.AnyRequest, now time.Time) bool {
	return s.cfg.IPLimiter.Allow("ip:"+s.clientIP(req.Header(), req.Peer().Addr), now)
}

func (s *Service) LoginWithPassword(ctx context.Context, req *connect.Request[stdloginv1.LoginWithPasswordRequest]) (*connect.Response[stdloginv1.LoginWithPasswordResponse], error) {
	now := s.now()
	if !s.allowIP(req, now) {
		return nil, errRateLimited
	}
	email, ok := NormalizeEmail(req.Msg.GetEmail())
	if !ok {
		s.cfg.Hasher.Verify(req.Msg.GetPassword(), "")
		return nil, errInvalidCredentials
	}

	u, err := s.cfg.Store.GetUserByEmail(ctx, email)
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.cfg.Hasher.Verify(req.Msg.GetPassword(), "")
		return nil, errInvalidCredentials
	case err != nil:
		return nil, s.internal(ctx, "get user", err)
	}

	if now.Before(u.LockedUntil) {
		s.cfg.Hasher.Verify(req.Msg.GetPassword(), "")
		return nil, errInvalidCredentials
	}

	if !s.cfg.Hasher.Verify(req.Msg.GetPassword(), u.PasswordHash) {
		if u.PasswordHash == "" {
			return nil, errInvalidCredentials
		}
		u.FailedLogins++
		if s.cfg.MaxFailedLogins > 0 && u.FailedLogins >= s.cfg.MaxFailedLogins {
			u.FailedLogins = 0
			u.LockedUntil = now.Add(s.cfg.LockoutDuration)
			s.cfg.Logger.WarnContext(ctx, "password login locked", "user_id", u.ID)
		}
		u.UpdatedAt = now
		if err := s.cfg.Store.UpdateUser(ctx, u); err != nil {
			return nil, s.internal(ctx, "record failed login", err)
		}
		return nil, errInvalidCredentials
	}

	dirty := false
	if u.FailedLogins != 0 || !u.LockedUntil.IsZero() {
		u.FailedLogins, u.LockedUntil, dirty = 0, time.Time{}, true
	}
	if s.cfg.Hasher.NeedsRehash(u.PasswordHash) {
		if h, err := s.cfg.Hasher.Hash(req.Msg.GetPassword()); err == nil {
			u.PasswordHash, dirty = h, true
		}
	}
	if dirty {
		u.UpdatedAt = now
		if err := s.cfg.Store.UpdateUser(ctx, u); err != nil {
			return nil, s.internal(ctx, "update user", err)
		}
	}

	tp, err := s.startSession(ctx, u, MethodPassword, now, now)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&stdloginv1.LoginWithPasswordResponse{Tokens: tp}), nil
}

func (s *Service) StartEmailLogin(ctx context.Context, req *connect.Request[stdloginv1.StartEmailLoginRequest]) (*connect.Response[stdloginv1.StartEmailLoginResponse], error) {
	now := s.now()
	if !s.allowIP(req, now) {
		return nil, errRateLimited
	}
	email, ok := NormalizeEmail(req.Msg.GetEmail())
	if !ok {
		return nil, errInvalidEmail
	}
	resp := connect.NewResponse(&stdloginv1.StartEmailLoginResponse{})

	// Over the per-address limit: report success anyway so the response
	// says nothing about the address, but send nothing (anti mail-bombing).
	if !s.cfg.EmailLimiter.Allow("email:"+email, now) {
		return resp, nil
	}
	if !s.cfg.AllowSignup {
		if _, err := s.cfg.Store.GetUserByEmail(ctx, email); errors.Is(err, store.ErrNotFound) {
			return resp, nil
		} else if err != nil {
			return nil, s.internal(ctx, "get user", err)
		}
	}

	tok, hash := token.NewOpaque()
	lt := &store.LoginToken{Hash: hash, Email: email, ExpiresAt: now.Add(s.cfg.LoginTokenTTL), CreatedAt: now}
	if err := s.cfg.Store.CreateLoginToken(ctx, lt); err != nil {
		return nil, s.internal(ctx, "create login token", err)
	}
	link, err := loginLink(s.cfg.LoginLinkURL, tok)
	if err != nil {
		return nil, s.internal(ctx, "build login link", err)
	}

	// Send off the request path so response timing doesn't depend on mail
	// delivery (or on whether we chose to send).
	go func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if err := s.cfg.Mailer.SendLoginLink(ctx, email, link, lt.ExpiresAt); err != nil {
			s.cfg.Logger.ErrorContext(ctx, "send login link", "err", err)
		}
	}()
	return resp, nil
}

func loginLink(base, tok string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("token", tok)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (s *Service) CompleteEmailLogin(ctx context.Context, req *connect.Request[stdloginv1.CompleteEmailLoginRequest]) (*connect.Response[stdloginv1.CompleteEmailLoginResponse], error) {
	now := s.now()
	if !s.allowIP(req, now) {
		return nil, errRateLimited
	}
	lt, err := s.cfg.Store.ConsumeLoginToken(ctx, token.Hash(req.Msg.GetLoginToken()))
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, errInvalidToken
	case err != nil:
		return nil, s.internal(ctx, "consume login token", err)
	case !now.Before(lt.ExpiresAt):
		return nil, errInvalidToken
	}

	u, err := s.cfg.Store.GetUserByEmail(ctx, lt.Email)
	if errors.Is(err, store.ErrNotFound) {
		if !s.cfg.AllowSignup {
			return nil, errInvalidToken
		}
		u, err = s.createUser(ctx, lt.Email, now)
	}
	if err != nil {
		return nil, s.internal(ctx, "load user", err)
	}

	tp, err := s.startSession(ctx, u, MethodEmail, now, now)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&stdloginv1.CompleteEmailLoginResponse{Tokens: tp}), nil
}

func (s *Service) createUser(ctx context.Context, email string, now time.Time) (*store.User, error) {
	u := &store.User{ID: token.NewID(), Email: email, CreatedAt: now, UpdatedAt: now}
	err := s.cfg.Store.CreateUser(ctx, u)
	if errors.Is(err, store.ErrAlreadyExists) {
		// Lost a race with a concurrent first login for the same address.
		return s.cfg.Store.GetUserByEmail(ctx, email)
	}
	if err != nil {
		return nil, err
	}
	s.cfg.Logger.InfoContext(ctx, "user created", "user_id", u.ID)
	return u, nil
}

func (s *Service) RefreshSession(ctx context.Context, req *connect.Request[stdloginv1.RefreshSessionRequest]) (*connect.Response[stdloginv1.RefreshSessionResponse], error) {
	now := s.now()
	rt, err := s.cfg.Store.UseRefreshToken(ctx, token.Hash(req.Msg.GetRefreshToken()), now)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, errInvalidToken
	case errors.Is(err, store.ErrAlreadyUsed):
		// Either the client retried or the token was stolen; we can't tell
		// which, so kill the session for both parties.
		s.cfg.Logger.WarnContext(ctx, "refresh token reuse; revoking session", "user_id", rt.UserID, "session_id", rt.SessionID)
		if err := s.cfg.Store.RevokeSession(ctx, rt.SessionID, now); err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, s.internal(ctx, "revoke session", err)
		}
		return nil, errInvalidToken
	case err != nil:
		return nil, s.internal(ctx, "use refresh token", err)
	case !now.Before(rt.ExpiresAt):
		return nil, errInvalidToken
	}

	sess, u, err := s.liveSession(ctx, rt.SessionID)
	if err != nil {
		return nil, err
	}
	tp, err := s.issueTokens(ctx, u, sess, now)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&stdloginv1.RefreshSessionResponse{Tokens: tp}), nil
}

// liveSession loads a session and its user, failing with errInvalidToken if
// the session has been revoked directly or by a password change.
func (s *Service) liveSession(ctx context.Context, id string) (*store.Session, *store.User, error) {
	sess, err := s.cfg.Store.GetSession(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil, errInvalidToken
	} else if err != nil {
		return nil, nil, s.internal(ctx, "get session", err)
	}
	if !sess.RevokedAt.IsZero() {
		return nil, nil, errInvalidToken
	}
	u, err := s.cfg.Store.GetUser(ctx, sess.UserID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil, errInvalidToken
	} else if err != nil {
		return nil, nil, s.internal(ctx, "get user", err)
	}
	if sess.Generation != u.SessionGeneration {
		return nil, nil, errInvalidToken
	}
	return sess, u, nil
}

func (s *Service) Logout(ctx context.Context, req *connect.Request[stdloginv1.LogoutRequest]) (*connect.Response[stdloginv1.LogoutResponse], error) {
	now := s.now()
	resp := connect.NewResponse(&stdloginv1.LogoutResponse{})
	rt, err := s.cfg.Store.UseRefreshToken(ctx, token.Hash(req.Msg.GetRefreshToken()), now)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return resp, nil // idempotent
	case err != nil && !errors.Is(err, store.ErrAlreadyUsed):
		return nil, s.internal(ctx, "use refresh token", err)
	}
	if err := s.cfg.Store.RevokeSession(ctx, rt.SessionID, now); err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, s.internal(ctx, "revoke session", err)
	}
	return resp, nil
}

func (s *Service) SetPassword(ctx context.Context, req *connect.Request[stdloginv1.SetPasswordRequest]) (*connect.Response[stdloginv1.SetPasswordResponse], error) {
	now := s.now()
	raw, ok := strings.CutPrefix(req.Header().Get("Authorization"), "Bearer ")
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("missing bearer token"))
	}
	claims, err := s.cfg.Issuer.Verify(raw, now)
	if err != nil {
		return nil, errInvalidToken
	}
	sess, u, err := s.liveSession(ctx, claims.SessionID)
	if err != nil {
		return nil, err
	}
	if u.ID != claims.Subject {
		return nil, errInvalidToken
	}
	if now.Sub(sess.AuthTime) > s.cfg.ReauthWindow {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("recent login required"))
	}
	if err := password.Validate(req.Msg.GetNewPassword()); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	h, err := s.cfg.Hasher.Hash(req.Msg.GetNewPassword())
	if err != nil {
		return nil, s.internal(ctx, "hash password", err)
	}
	u.PasswordHash = h
	u.FailedLogins, u.LockedUntil = 0, time.Time{}
	u.SessionGeneration++ // revokes every existing session
	u.UpdatedAt = now
	if err := s.cfg.Store.UpdateUser(ctx, u); err != nil {
		return nil, s.internal(ctx, "update user", err)
	}

	tp, err := s.startSession(ctx, u, sess.AuthMethod, sess.AuthTime, now)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&stdloginv1.SetPasswordResponse{Tokens: tp}), nil
}

func (s *Service) startSession(ctx context.Context, u *store.User, method string, authTime, now time.Time) (*stdloginv1.TokenPair, error) {
	sess := &store.Session{ID: token.NewID(), UserID: u.ID, AuthTime: authTime, AuthMethod: method, Generation: u.SessionGeneration, CreatedAt: now}
	if err := s.cfg.Store.CreateSession(ctx, sess); err != nil {
		return nil, s.internal(ctx, "create session", err)
	}
	return s.issueTokens(ctx, u, sess, now)
}

func (s *Service) issueTokens(ctx context.Context, u *store.User, sess *store.Session, now time.Time) (*stdloginv1.TokenPair, error) {
	refresh, hash := token.NewOpaque()
	rt := &store.RefreshToken{Hash: hash, SessionID: sess.ID, UserID: u.ID, ExpiresAt: now.Add(s.cfg.RefreshTTL), CreatedAt: now}
	if err := s.cfg.Store.CreateRefreshToken(ctx, rt); err != nil {
		return nil, s.internal(ctx, "create refresh token", err)
	}
	access, exp, err := s.cfg.Issuer.Issue(token.Subject{
		UserID:     u.ID,
		Email:      u.Email,
		SessionID:  sess.ID,
		AuthTime:   sess.AuthTime,
		AuthMethod: sess.AuthMethod,
	}, now)
	if err != nil {
		return nil, s.internal(ctx, "sign access token", fmt.Errorf("sign: %w", err))
	}
	return &stdloginv1.TokenPair{
		AccessToken:           access,
		AccessTokenExpiresAt:  timestamppb.New(exp),
		RefreshToken:          refresh,
		RefreshTokenExpiresAt: timestamppb.New(rt.ExpiresAt),
		TokenType:             "Bearer",
		UserId:                u.ID,
	}, nil
}
