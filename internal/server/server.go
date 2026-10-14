// Package server mounts the AuthService and supporting endpoints on an
// http.Handler.
package server

import (
	"net/http"

	"connectrpc.com/connect"
	"connectrpc.com/vanguard"

	"github.com/scandeezy/std-login/gen/api/v1/apiv1connect"
	"github.com/scandeezy/std-login/internal/auth"
	"github.com/scandeezy/std-login/internal/token"
)

// maxRequestBytes bounds request bodies; no legitimate request comes close.
const maxRequestBytes = 16 << 10

// Handler serves:
//
//	/api.v1.AuthService/*   Connect, gRPC and gRPC-Web
//	google.api.http paths   REST, as annotated in proto/api/v1/auth.proto
//	/.well-known/jwks.json  public key(s) for verifying access tokens
//	/healthz                liveness
//
// RPC paths go straight to the Connect handler. Everything else goes to a
// Vanguard transcoder, which serves the REST routes from the proto annotations
// and forwards them to the same handler. (Behind Vanguard, a plain JSON POST to
// an RPC path would be treated as REST unless it sent Connect-Protocol-Version.)
func Handler(svc *auth.Service, issuer *token.Issuer) (http.Handler, error) {
	mux := http.NewServeMux()
	path, h := apiv1connect.NewAuthServiceHandler(svc, connect.WithReadMaxBytes(maxRequestBytes))
	transcoder, err := vanguard.NewTranscoder([]*vanguard.Service{
		vanguard.NewService(path, h, vanguard.WithMaxMessageBufferBytes(maxRequestBytes)),
	})
	if err != nil {
		return nil, err
	}
	mux.Handle(path, noStore(h))
	mux.Handle("/", noStore(transcoder))

	jwks := issuer.JWKS()
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Write(jwks)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	})
	return mux, nil
}

// noStore keeps credentials in responses out of caches.
func noStore(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	})
}
