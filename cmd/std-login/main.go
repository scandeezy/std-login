// Command std-login runs the login service.
//
//	std-login            serve (configured via environment, see internal/config)
//	std-login keygen     print a new Ed25519 signing key (PKCS#8 PEM) to stdout
package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/scandeezy/std-login/internal/auth"
	"github.com/scandeezy/std-login/internal/config"
	"github.com/scandeezy/std-login/internal/mail"
	"github.com/scandeezy/std-login/internal/password"
	"github.com/scandeezy/std-login/internal/ratelimit"
	"github.com/scandeezy/std-login/internal/server"
	"github.com/scandeezy/std-login/internal/store"
	"github.com/scandeezy/std-login/internal/store/memory"
	"github.com/scandeezy/std-login/internal/store/sqlite"
	"github.com/scandeezy/std-login/internal/token"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "keygen" {
		b, err := token.EncodeKeyPEM(token.GenerateKey())
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Stdout.Write(b)
		return
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(logger); err != nil {
		logger.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := openStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer st.Close()

	key, err := loadKey(cfg, logger)
	if err != nil {
		return err
	}
	issuer := token.NewIssuer(key, cfg.JWTIssuer, cfg.JWTAudience, cfg.AccessTTL)

	var sender mail.Sender
	switch cfg.MailDriver {
	case "log":
		sender = mail.LogSender{Logger: logger}
	case "smtp":
		sender = mail.SMTPSender{Addr: cfg.SMTPAddr, Username: cfg.SMTPUsername, Password: cfg.SMTPPassword, From: cfg.MailFrom}
	default:
		return fmt.Errorf("unknown MAIL_DRIVER %q", cfg.MailDriver)
	}

	svc := auth.New(auth.Config{
		Store:             st,
		Hasher:            password.NewHasher(password.DefaultParams),
		Issuer:            issuer,
		Mailer:            sender,
		Logger:            logger,
		IPLimiter:         ratelimit.NewMemory(cfg.RateLimitPerIP, time.Minute),
		EmailLimiter:      ratelimit.NewMemory(cfg.RateLimitPerEmail, time.Hour),
		RefreshTTL:        cfg.RefreshTTL,
		LoginTokenTTL:     cfg.LoginTokenTTL,
		LoginLinkURL:      cfg.LoginLinkURL,
		AllowSignup:       cfg.AllowSignup,
		MaxFailedLogins:   cfg.MaxFailedLogins,
		LockoutDuration:   cfg.LockoutDuration,
		ReauthWindow:      cfg.ReauthWindow,
		TrustProxyHeaders: cfg.TrustProxyHeaders,
	})

	go purgeLoop(ctx, st, logger)

	// Serve HTTP/1.1 plus cleartext HTTP/2 so gRPC clients work without TLS
	// termination here; terminate TLS at the load balancer.
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           server.Handler(svc, issuer),
		Protocols:         &protocols,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	errc := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", cfg.ListenAddr, "store", cfg.StoreDriver, "dev", cfg.Dev)
		errc <- srv.ListenAndServe()
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func openStore(ctx context.Context, cfg *config.Config) (store.Store, error) {
	switch cfg.StoreDriver {
	case "sqlite":
		return sqlite.Open(ctx, cfg.SQLitePath)
	case "memory":
		return memory.New(), nil
	default:
		return nil, fmt.Errorf("unknown STORE_DRIVER %q", cfg.StoreDriver)
	}
}

func loadKey(cfg *config.Config, logger *slog.Logger) (ed25519.PrivateKey, error) {
	if cfg.JWTPrivateKeyFile != "" {
		return token.LoadKeyFile(cfg.JWTPrivateKeyFile)
	}
	logger.Warn("no JWT_PRIVATE_KEY_FILE; using an ephemeral key (tokens will not survive restart)")
	return token.GenerateKey(), nil
}

func purgeLoop(ctx context.Context, st store.Store, logger *slog.Logger) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := st.PurgeExpired(ctx, time.Now()); err != nil {
				logger.Error("purge expired tokens", "err", err)
			}
		}
	}
}
