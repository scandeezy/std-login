// Package server mounts the AuthService and supporting endpoints on an
// http.Handler.
package server

import (
	"net/http"

	"connectrpc.com/connect"

	"github.com/scandeezy/std-login/gen/stdlogin/v1/stdloginv1connect"
	"github.com/scandeezy/std-login/internal/auth"
	"github.com/scandeezy/std-login/internal/token"
)

// maxRequestBytes bounds request bodies; no legitimate request comes close.
const maxRequestBytes = 16 << 10

// Handler serves:
//
//	/stdlogin.v1.AuthService/*  Connect, gRPC and gRPC-Web
//	/.well-known/jwks.json      public key(s) for verifying access tokens
//	/healthz                    liveness
func Handler(svc *auth.Service, issuer *token.Issuer) http.Handler {
	mux := http.NewServeMux()
	path, h := stdloginv1connect.NewAuthServiceHandler(svc, connect.WithReadMaxBytes(maxRequestBytes))
	mux.Handle(path, noStore(h))

	jwks := issuer.JWKS()
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Write(jwks)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	})
	return mux
}

// noStore keeps credentials in responses out of caches.
func noStore(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	})
}
