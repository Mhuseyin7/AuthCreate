package main

import (
	"crypto/subtle"
	"net"
	"net/http"
	"strings"
)

// admin separates AuthCrate's control plane from the identities issued by the
// provider. Development accepts local control requests; SELF_HOSTED requires a
// separately configured bearer credential and rejects cross-origin mutations.
func (s *Server) admin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.mode != "SELF_HOSTED" && !isLoopbackRequest(r) {
			respond(w, http.StatusForbidden, map[string]string{"error": "development control plane is local-only"})
			return
		}
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

func isLoopbackRequest(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
