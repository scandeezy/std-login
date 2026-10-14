# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Scope

A Go login service that issues JWTs. It handles **authentication only**: email/password login, emailed single-use login links, and the security of the resulting sessions. Do not add authorization, roles, profiles or general user management. Those belong to the services that consume the JWT.

## Commands

```sh
make test                                   # go test -race ./...  (Redis tests use miniredis)
REDIS_URL=redis://localhost:6379/15 go test ./internal/ratelimit/...   # also run against a real Redis
go test ./internal/auth -run TestLockout    # single test
make lint                                   # buf lint + go vet + gofmt check
make generate                               # regenerate gen/ after editing proto/
make run                                    # dev server on :8080 (DEV=true: ephemeral key, login links logged)
```

buf, protoc-gen-go and protoc-gen-connect-go are pinned as `tool` dependencies in `go.mod` (run via `go tool ...`); nothing needs a global install. `gen/` is generated and committed. Never hand-edit it.

## Architecture

- **API contract**: `proto/api/v1/auth.proto` is the source of truth. It is served with connect-go, so each RPC is reachable as gRPC, gRPC-Web, and plain HTTP/JSON at `POST /api.v1.AuthService/<Method>`. RPCs with a `google.api.http` annotation are also served as REST at that path (e.g. `POST /api/session/pwlogin`) through a Vanguard transcoder (`connectrpc.com/vanguard`, pinned to v0.4.x because v0.5+ requires connect-go v2). Other paths fall through to Vanguard, while RPC paths go straight to Connect, because Vanguard would treat a JSON POST without `Connect-Protocol-Version` as REST. Changes must stay wire-compatible (`buf breaking` is configured with FILE rules).
- **Request flow**: `cmd/std-login/main.go` loads config from env (`internal/config`) and wires the dependencies into `auth.Config`. `internal/server` mounts the handler plus `/.well-known/jwks.json` and `/healthz`. All business logic is in `internal/auth/auth.go`.
- **Storage facade**: `internal/store/store.go` defines `store.Store`; implementations are `memory` (tests) and `sqlite` (local dev). The interface is deliberately NoSQL-friendly, because production may use MySQL or a NoSQL store. When changing it, keep to these rules:
  - Single-record operations by key only, with no joins or multi-record transactions.
  - Atomicity is limited to conditional single-record writes (`ConsumeLoginToken`, `UseRefreshToken`).
  - Bulk invalidation goes through a counter (`User.SessionGeneration` must equal `Session.Generation`), never through multi-row updates.
  - Every implementation must pass `internal/store/storetest.Run` (includes concurrency tests). Add new backends as a package plus a one-line conformance test.
- **Rate limiting**: `ratelimit.Limiter` has two implementations, chosen with `RATE_LIMIT_DRIVER`:
  - `ratelimit.Memory`: per process, the default.
  - `redislimit`: shared across instances. It uses fixed windows aligned to the epoch and a single `MULTI` of INCR+PEXPIRE per call, and hashes keys so IPs and emails aren't stored in Redis.

  Both must pass `internal/ratelimit/ratelimittest.Run`. Limiter errors **fail open** in `auth` (logged), because a Redis outage must not become a login outage; account lockout in the store remains the brute-force backstop. Startup, however, fails if Redis is unreachable.
- **Mail**: `mail.Sender` (log/SMTP) is swappable.

## Security invariants (preserve these)

These are documented at the top of `internal/auth/auth.go` and covered by `internal/auth/auth_test.go`:

- **No account enumeration.** Every password-login failure (unknown user, wrong password, no password, locked) returns the same `Unauthenticated` error after the same argon2 work (`Hasher.Verify` with an empty hash burns a dummy verify). `StartEmailLogin` always returns success and sends mail in a goroutine. When the per-email rate limit is hit it silently sends nothing.
- **No separate registration.** An account is created on the first successful email login (`ALLOW_SIGNUP`). `SetPassword` needs a bearer access token whose `auth_time` is within `ReauthWindow`. Refreshes carry the original `auth_time`, so a refreshed token can't be used to set a password. Setting a password bumps `SessionGeneration`, which revokes all sessions, and returns a new token pair.
- **Opaque tokens.** Login and refresh tokens are 256-bit random values, stored only as SHA-256 hashes (`token.Hash`), and single use. Reusing a refresh token revokes its whole session.
- **Time handling.** Stores keep millisecond precision, so the service truncates `now` to milliseconds. Use the injected `Config.Now` instead of calling `time.Now()` in `auth`.
- **JWTs.** Signed with EdDSA/Ed25519, with `kid` derived from the public key. Claims: `sub` (user ID), `email`, `sid`, `auth_time`, `amr` (`pwd` or `email`).

## CORS: intentionally not supported

The service sends no CORS headers, so browsers can only call it from the same origin (e.g. behind a reverse proxy that routes `/api.v1.AuthService/*` on the app's domain). Cross-origin JSON/Authorization requests fail the browser's preflight. Preflight-free "simple" requests (form/text bodies) are rejected by Connect with 415 before any RPC runs. Don't add CORS middleware, and make sure no proxy, gateway or CDN in front adds `Access-Control-Allow-Origin`, unless the product decision changes. `TestNoCORS` in `internal/server/server_test.go` enforces this. If CORS is ever wanted, decide where browsers keep the refresh token before enabling it.

## Testing conventions

Auth tests run end to end through `httptest` and the generated connect client (`newHarness` in `auth_test.go`). They use a fake clock and a capturing mailer (`outbox.next` / `outbox.none`). Use cheap argon2 params in tests (`Memory: 1024, Iterations: 1`).
