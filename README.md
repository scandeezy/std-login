# std-login

A Go login service that issues JWTs. It handles authentication only: proving who a user is and keeping the resulting sessions secure. It does not handle authorization, profiles or user management.

- **Login methods:** email + password, or a short-lived single-use link sent by email ("magic link").
- **Interface:** protobuf ([`proto/api/v1/auth.proto`](proto/api/v1/auth.proto)), served with [Connect](https://connectrpc.com). The same endpoints accept gRPC, gRPC-Web, and plain HTTP/JSON (`POST /api.v1.AuthService/<Method>`), so they work for both web and mobile clients.
- **Tokens:** EdDSA-signed access JWT (default 15 min) plus an opaque refresh token. Refresh tokens rotate on every use and can be revoked. Downstream services verify JWTs with the public key at `/.well-known/jwks.json`.
- **Storage:** behind the `store.Store` interface. It ships with SQLite (local dev, single instance) and in-memory (tests) implementations. The interface does only single-record, key-based operations, so MySQL or NoSQL backends can be added.

## Quick start

```sh
make run      # :8080, SQLite file std-login.db; login links are written to the log
make test
```

### Trying it with curl

With `make run` going, walk through the full flow from another terminal (uses `jq`):

```sh
BASE=http://localhost:8080
RPC=$BASE/api.v1.AuthService

# Health check and the public keys for verifying JWTs
curl -s $BASE/healthz
curl -s $BASE/.well-known/jwks.json

# Request a login link (creates the account on first use). In dev mode it is
# logged as "login link (dev mail sender)"; copy the token= value from it.
curl -s -XPOST $RPC/StartEmailLogin -H 'Content-Type: application/json' \
  -d '{"email":"me@example.com"}'
LOGIN_TOKEN=<paste token here>

# Exchange it for a token pair
RESP=$(curl -s -XPOST $RPC/CompleteEmailLogin -H 'Content-Type: application/json' \
  -d "{\"loginToken\":\"$LOGIN_TOKEN\"}")
AT=$(echo $RESP | jq -r .tokens.accessToken)
RT=$(echo $RESP | jq -r .tokens.refreshToken)

# Inspect the JWT claims (sub, email, sid, auth_time, amr)
echo $AT | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null; echo

# Refresh. Refresh tokens are single use, so keep the new one; replaying the
# old one revokes the session.
RESP=$(curl -s -XPOST $RPC/RefreshSession -H 'Content-Type: application/json' \
  -d "{\"refreshToken\":\"$RT\"}")
RT=$(echo $RESP | jq -r .tokens.refreshToken)

# Set a password (min 10 characters). Needs an access token from a login
# within REAUTH_WINDOW (10 min), not a refresh. Revokes all other sessions and
# returns a new token pair.
RESP=$(curl -s -XPOST $RPC/SetPassword -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $AT" -d '{"newPassword":"correct horse battery staple"}')
RT=$(echo $RESP | jq -r .tokens.refreshToken)

# Log in with the password. Any failure returns
# {"code":"unauthenticated","message":"invalid credentials"}.
curl -s -XPOST $RPC/LoginWithPassword -H 'Content-Type: application/json' \
  -d '{"email":"me@example.com","password":"correct horse battery staple"}' | jq

# Log out (revokes the session)
curl -s -XPOST $RPC/Logout -H 'Content-Type: application/json' \
  -d "{\"refreshToken\":\"$RT\"}"
```

The same RPCs are also served as REST at the paths given by the `google.api.http` annotations in the proto (`/api/session/pwlogin`, `/emlogin`, `/emcomplete`, `/refresh`, `/logout`, `/setpw`), with the request message as the JSON body. For example:

```sh
curl -s -XPOST $BASE/api/session/emlogin -H 'Content-Type: application/json' \
  -d '{"email":"me@example.com"}'
```

REST errors are returned as `google.rpc.Status` JSON with a matching HTTP status (for example 401 for invalid credentials).

JSON fields use camelCase (snake_case is also accepted), and the `Content-Type: application/json` header is required (otherwise 415). Repeated runs can hit the rate limits: 30 requests/minute per IP and 5 login emails/hour per address. Over the email limit, no link is logged and the call still returns `{}`.

## Running multiple instances

Set `RATE_LIMIT_DRIVER=redis` and `REDIS_URL` so rate limits are shared across instances. The default in-memory limiter enforces limits per process. Users, tokens and sessions are already shared through the store.

## Account model

There is no separate registration call. The first time an address completes an email login, an account is created for it (set `ALLOW_SIGNUP=false` to turn this off). The user can then call `SetPassword` with a recent access token. As a result, a password can only be attached to an address whose ownership has been proven. Email login also serves as "forgot password".

## Configuration

Configuration comes from environment variables; see [`internal/config/config.go`](internal/config/config.go) for the full list and defaults. Outside `DEV=true`, the service refuses to start unless all of these are set:

- `JWT_PRIVATE_KEY_FILE` (generate one with `make keygen`)
- `JWT_ISSUER`, typically the service's public URL
- `JWT_AUDIENCE`, the apps that should accept its tokens
- `LOGIN_LINK_URL`, an absolute `https` URL for emailed login links
- a real mail driver (`MAIL_DRIVER=smtp`)
- a persistent store

With `DEV=true`, the issuer and login link fall back to local placeholders.
