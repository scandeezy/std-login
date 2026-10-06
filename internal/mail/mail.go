// Package mail delivers login links. The service depends only on Sender.
package mail

import (
	"context"
	"fmt"
	"log/slog"
	"net/smtp"
	"strings"
	"time"
)

type Sender interface {
	SendLoginLink(ctx context.Context, to, link string, expiresAt time.Time) error
}

// LogSender writes the link to the log instead of sending it. Development only:
// the link is a credential.
type LogSender struct {
	Logger *slog.Logger
}

func (s LogSender) SendLoginLink(ctx context.Context, to, link string, expiresAt time.Time) error {
	s.Logger.InfoContext(ctx, "login link (dev mail sender)", "to", to, "link", link, "expires_at", expiresAt)
	return nil
}

// SMTPSender sends via an SMTP relay. net/smtp upgrades to STARTTLS when the
// server offers it and refuses PLAIN auth over an unencrypted remote link.
type SMTPSender struct {
	Addr     string // host:port
	Username string
	Password string
	From     string
}

func (s SMTPSender) SendLoginLink(_ context.Context, to, link string, expiresAt time.Time) error {
	if strings.ContainsAny(to, "\r\n") {
		return fmt.Errorf("invalid recipient")
	}
	var auth smtp.Auth
	if s.Username != "" {
		host, _, _ := strings.Cut(s.Addr, ":")
		auth = smtp.PlainAuth("", s.Username, s.Password, host)
	}
	msg := strings.Join([]string{
		"From: " + s.From,
		"To: " + to,
		"Subject: Your sign-in link",
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"Use this link to sign in. It expires at " + expiresAt.UTC().Format(time.RFC1123) + " and can be used once.",
		"",
		link,
		"",
		"If you did not request this, you can ignore this email.",
	}, "\r\n")
	return smtp.SendMail(s.Addr, auth, s.From, []string{to}, []byte(msg))
}
