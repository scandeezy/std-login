package config

import (
	"strings"
	"testing"
)

// prodEnv is a minimal valid non-dev configuration.
var prodEnv = map[string]string{
	"DEV":                  "false",
	"JWT_PRIVATE_KEY_FILE": "/etc/std-login/jwt-key.pem",
	"JWT_ISSUER":           "https://login.example.com",
	"JWT_AUDIENCE":         "web,mobile",
	"LOGIN_LINK_URL":       "https://app.example.com/login",
	"MAIL_DRIVER":          "smtp",
	"SMTP_ADDR":            "smtp.example.com:587",
	"MAIL_FROM":            "login@example.com",
	"STORE_DRIVER":         "sqlite",
	"RATE_LIMIT_DRIVER":    "memory",
}

func load(t *testing.T, base map[string]string, overrides map[string]string) (*Config, error) {
	t.Helper()
	for k, v := range base {
		t.Setenv(k, v)
	}
	for k, v := range overrides {
		t.Setenv(k, v)
	}
	return Load()
}

func TestProdValid(t *testing.T) {
	c, err := load(t, prodEnv, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.JWTIssuer != "https://login.example.com" || len(c.JWTAudience) != 2 || c.LoginLinkURL != "https://app.example.com/login" {
		t.Errorf("config = %+v", c)
	}
}

func TestProdRequiresDomainSettings(t *testing.T) {
	for name, tc := range map[string]struct {
		override map[string]string
		wantErr  string
	}{
		"missing issuer":     {map[string]string{"JWT_ISSUER": ""}, "JWT_ISSUER is required"},
		"missing audience":   {map[string]string{"JWT_AUDIENCE": ""}, "JWT_AUDIENCE is required"},
		"blank audience":     {map[string]string{"JWT_AUDIENCE": " , "}, "JWT_AUDIENCE is required"},
		"missing login link": {map[string]string{"LOGIN_LINK_URL": ""}, "LOGIN_LINK_URL is required"},
		"http login link":    {map[string]string{"LOGIN_LINK_URL": "http://app.example.com/login"}, "must use https"},
		"relative link":      {map[string]string{"LOGIN_LINK_URL": "/login"}, "absolute URL"},
		"no host":            {map[string]string{"LOGIN_LINK_URL": "https:///login"}, "absolute URL"},
		"other scheme":       {map[string]string{"LOGIN_LINK_URL": "myapp://login"}, "absolute URL"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := load(t, prodEnv, tc.override)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestDevDefaults(t *testing.T) {
	c, err := load(t, map[string]string{
		"DEV":            "true",
		"JWT_ISSUER":     "",
		"JWT_AUDIENCE":   "",
		"LOGIN_LINK_URL": "",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.JWTIssuer != "std-login-dev" || c.LoginLinkURL != "http://localhost:3000/login" {
		t.Errorf("dev defaults not applied: %+v", c)
	}
	// Dev still rejects malformed links.
	if _, err := load(t, map[string]string{"DEV": "true", "LOGIN_LINK_URL": "localhost:3000"}, nil); err == nil {
		t.Error("malformed dev link accepted")
	}
}
