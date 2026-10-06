# std-login

A Go login service that issues JWTs. It handles authentication only: proving who a user is and keeping the resulting sessions secure. It does not handle authorization, profiles or user management.

- **Login methods:** email + password, or a short-lived single-use link sent by email ("magic link").
- **Interface:** protobuf ([`proto/stdlogin/v1/auth.proto`](proto/stdlogin/v1/auth.proto)), served with [Connect](https://connectrpc.com). The same endpoints accept gRPC, gRPC-Web, and plain HTTP/JSON (`POST /stdlogin.v1.AuthService/<Method>`), so they work for both web and mobile clients.
- **Tokens:** EdDSA-signed access JWT (default 15 min) plus an opaque refresh token. Refresh tokens rotate on every use and can be revoked. Downstream services verify JWTs with the public key at `/.well-known/jwks.json`.
- **Storage:** behind the `store.Store` interface. It ships with SQLite (local dev, single instance) and in-memory (tests) implementations. The interface does only single-record, key-based operations, so MySQL or NoSQL backends can be added.

## Quick start

```sh
make run      # :8080, SQLite file std-login.db; login links are written to the log
make test
```

```sh
curl -XPOST localhost:8080/stdlogin.v1.AuthService/StartEmailLogin \
  -H 'Content-Type: application/json' -d '{"email":"me@example.com"}'
# copy the token from the logged link, then:
curl -XPOST localhost:8080/stdlogin.v1.AuthService/CompleteEmailLogin \
  -H 'Content-Type: application/json' -d '{"loginToken":"..."}'
```

## Running multiple instances

Set `RATE_LIMIT_DRIVER=redis` and `REDIS_URL` so rate limits are shared across instances. The default in-memory limiter enforces limits per process. Users, tokens and sessions are already shared through the store.

## Account model

There is no separate registration call. The first time an address completes an email login, an account is created for it (set `ALLOW_SIGNUP=false` to turn this off). The user can then call `SetPassword` with a recent access token. As a result, a password can only be attached to an address whose ownership has been proven. Email login also serves as "forgot password".

## Configuration

Configuration comes from environment variables; see [`internal/config/config.go`](internal/config/config.go) for the full list and defaults. Outside `DEV=true`, the service refuses to start without `JWT_PRIVATE_KEY_FILE` (generate one with `make keygen`), a real mail driver (`MAIL_DRIVER=smtp`), and a persistent store.
