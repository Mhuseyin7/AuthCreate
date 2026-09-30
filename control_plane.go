package main

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// admin separates AuthCrate's control plane from the identities issued by the
// provider. Development accepts local control requests; SELF_HOSTED requires a
// separately configured bearer credential and rejects cross-origin mutations.
func (s *Server) admin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if origin := r.Header.Get("Origin"); origin != "" && origin != s.issuer {
				respond(w, http.StatusForbidden, map[string]string{"error": "cross-origin control request rejected"})
				return
			}
		}
		if s.mode == "SELF_HOSTED" {
			provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if provided == r.Header.Get("Authorization") || subtle.ConstantTimeCompare([]byte(provided), []byte(s.adminToken)) != 1 {
				w.Header().Set("WWW-Authenticate", `Bearer realm="authcrate-admin"`)
				respond(w, http.StatusUnauthorized, map[string]string{"error": "admin authentication required"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
