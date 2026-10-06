// Package config loads service configuration from environment variables.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ListenAddr string // LISTEN_ADDR

	StoreDriver string // STORE_DRIVER: sqlite | memory
	SQLitePath  string // SQLITE_PATH

	JWTIssuer         string        // JWT_ISSUER
	JWTAudience       []string      // JWT_AUDIENCE (comma separated)
	JWTPrivateKeyFile string        // JWT_PRIVATE_KEY_FILE (PKCS#8 PEM Ed25519)
	AccessTTL         time.Duration // ACCESS_TOKEN_TTL
	RefreshTTL        time.Duration // REFRESH_TOKEN_TTL
	LoginTokenTTL     time.Duration // LOGIN_TOKEN_TTL
	LoginLinkURL      string        // LOGIN_LINK_URL
	AllowSignup       bool          // ALLOW_SIGNUP

	MaxFailedLogins int           // MAX_FAILED_LOGINS
	LockoutDuration time.Duration // LOCKOUT_DURATION
	ReauthWindow    time.Duration // REAUTH_WINDOW

	RateLimitPerIP    int  // RATE_LIMIT_PER_IP (requests/minute)
	RateLimitPerEmail int  // RATE_LIMIT_PER_EMAIL (login emails/hour)
	TrustProxyHeaders bool // TRUST_PROXY_HEADERS

	MailDriver   string // MAIL_DRIVER: log | smtp
	SMTPAddr     string // SMTP_ADDR
	SMTPUsername string // SMTP_USERNAME
	SMTPPassword string // SMTP_PASSWORD
	MailFrom     string // MAIL_FROM

	// Dev relaxes production safety checks: allows an ephemeral signing key
	// and the log mail driver. DEV
	Dev bool
}

func Load() (*Config, error) {
	l := loader{}
	c := &Config{
		ListenAddr:        l.str("LISTEN_ADDR", ":8080"),
		StoreDriver:       l.str("STORE_DRIVER", "sqlite"),
		SQLitePath:        l.str("SQLITE_PATH", "std-login.db"),
		JWTIssuer:         l.str("JWT_ISSUER", "std-login"),
		JWTAudience:       l.list("JWT_AUDIENCE"),
		JWTPrivateKeyFile: l.str("JWT_PRIVATE_KEY_FILE", ""),
		AccessTTL:         l.dur("ACCESS_TOKEN_TTL", 15*time.Minute),
		RefreshTTL:        l.dur("REFRESH_TOKEN_TTL", 30*24*time.Hour),
		LoginTokenTTL:     l.dur("LOGIN_TOKEN_TTL", 10*time.Minute),
		LoginLinkURL:      l.str("LOGIN_LINK_URL", "http://localhost:3000/login"),
		AllowSignup:       l.bool("ALLOW_SIGNUP", true),
		MaxFailedLogins:   l.int("MAX_FAILED_LOGINS", 10),
		LockoutDuration:   l.dur("LOCKOUT_DURATION", 15*time.Minute),
		ReauthWindow:      l.dur("REAUTH_WINDOW", 10*time.Minute),
		RateLimitPerIP:    l.int("RATE_LIMIT_PER_IP", 30),
		RateLimitPerEmail: l.int("RATE_LIMIT_PER_EMAIL", 5),
		TrustProxyHeaders: l.bool("TRUST_PROXY_HEADERS", false),
		MailDriver:        l.str("MAIL_DRIVER", "log"),
		SMTPAddr:          l.str("SMTP_ADDR", ""),
		SMTPUsername:      l.str("SMTP_USERNAME", ""),
		SMTPPassword:      l.str("SMTP_PASSWORD", ""),
		MailFrom:          l.str("MAIL_FROM", ""),
		Dev:               l.bool("DEV", false),
	}
	if l.err != nil {
		return nil, l.err
	}
	return c, c.validate()
}

func (c *Config) validate() error {
	if !c.Dev {
		if c.JWTPrivateKeyFile == "" {
			return fmt.Errorf("JWT_PRIVATE_KEY_FILE is required (or set DEV=true for an ephemeral key)")
		}
		if c.MailDriver == "log" {
			return fmt.Errorf("MAIL_DRIVER=log writes login links to logs; set DEV=true to allow it")
		}
		if c.StoreDriver == "memory" {
			return fmt.Errorf("STORE_DRIVER=memory loses all data on restart; set DEV=true to allow it")
		}
	}
	if c.MailDriver == "smtp" && (c.SMTPAddr == "" || c.MailFrom == "") {
		return fmt.Errorf("MAIL_DRIVER=smtp requires SMTP_ADDR and MAIL_FROM")
	}
	if c.AccessTTL <= 0 || c.RefreshTTL <= 0 || c.LoginTokenTTL <= 0 {
		return fmt.Errorf("token TTLs must be positive")
	}
	return nil
}

type loader struct{ err error }

func (l *loader) str(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func (l *loader) list(key string) []string {
	var out []string
	for _, s := range strings.Split(os.Getenv(key), ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func (l *loader) dur(key string, def time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil && l.err == nil {
		l.err = fmt.Errorf("%s: %w", key, err)
	}
	return d
}

func (l *loader) int(key string, def int) int {
	v, ok := os.LookupEnv(key)
	if !ok {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil && l.err == nil {
		l.err = fmt.Errorf("%s: %w", key, err)
	}
	return n
}

func (l *loader) bool(key string, def bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil && l.err == nil {
		l.err = fmt.Errorf("%s: %w", key, err)
	}
	return b
}
