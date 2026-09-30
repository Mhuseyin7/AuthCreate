package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func testServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	s, err := newServer("http://issuer.test")
	if err != nil {
		t.Fatal(err)
	}
	return s, httptest.NewServer(s.routes())
}
func TestDiscoveryConsistent(t *testing.T) {
	_, h := testServer(t)
	defer h.Close()
	r, err := http.Get(h.URL + "/.well-known/openid-configuration")
	if err != nil || r.StatusCode != 200 {
		t.Fatalf("discovery: %v, %v", r.StatusCode, err)
	}
	var d map[string]any
	json.NewDecoder(r.Body).Decode(&d)
	if d["jwks_uri"] != "http://issuer.test/.well-known/jwks.json" {
		t.Fatal("incorrect JWKS URI")
	}
}
func TestAuthorizationRejectsUnregisteredRedirect(t *testing.T) {
	_, h := testServer(t)
	defer h.Close()
	q := url.Values{"client_id": {"playground-client"}, "redirect_uri": {"http://evil.test/callback"}, "response_type": {"code"}, "scope": {"openid"}, "nonce": {"n"}, "code_challenge": {"abc"}, "code_challenge_method": {"S256"}}
	r, _ := http.Get(h.URL + "/authorize?" + q.Encode())
	if r.StatusCode != http.StatusBadRequest {
		t.Fatalf("got %d", r.StatusCode)
	}
}
func TestPKCEAndCodeSingleUse(t *testing.T) {
	s, h := testServer(t)
	defer h.Close()
	verifier := "this-is-a-long-enough-pkce-verifier-for-testing-123456789"
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])
	c := "manual-code"
	s.codes[c] = &Code{Value: c, ClientID: "playground-client", RedirectURI: "http://issuer.test/playground/callback", Subject: "normal-user", Scope: "openid offline_access", Challenge: challenge, Expires: timeNow().Add(time.Minute), AuthTime: timeNow()}
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {"playground-client"}, "code": {c}, "redirect_uri": {"http://issuer.test/playground/callback"}, "code_verifier": {verifier}}
	r, _ := http.Post(h.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if r.StatusCode != 200 {
		t.Fatalf("exchange got %d", r.StatusCode)
	}
	r, _ = http.Post(h.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if r.StatusCode != 400 {
		t.Fatalf("replay got %d", r.StatusCode)
	}
}
func TestWrongPKCEVerifierFails(t *testing.T) {
	s, h := testServer(t)
	defer h.Close()
	c := "pkce-code"
	s.codes[c] = &Code{Value: c, ClientID: "playground-client", RedirectURI: "http://issuer.test/playground/callback", Subject: "normal-user", Scope: "openid", Challenge: "not-the-verifier", Expires: timeNow().Add(time.Minute)}
	f := url.Values{"grant_type": {"authorization_code"}, "client_id": {"playground-client"}, "code": {c}, "redirect_uri": {"http://issuer.test/playground/callback"}, "code_verifier": {"bad"}}
	r, _ := http.Post(h.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(f.Encode()))
	if r.StatusCode != 400 {
		t.Fatal("PKCE bypass")
	}
}

// indirection keeps tests readable and makes clock replacement straightforward.
var timeNow = func() time.Time { return time.Now() }

func TestRefreshRotationAndRevocation(t *testing.T) {
	s, h := testServer(t)
	defer h.Close()
	s.refresh["old-refresh"] = &Refresh{Value: "old-refresh", ClientID: "playground-client", Subject: "normal-user", Scope: "openid offline_access", Expires: timeNow().Add(time.Hour)}
	f := url.Values{"grant_type": {"refresh_token"}, "client_id": {"playground-client"}, "refresh_token": {"old-refresh"}}
	r, _ := http.Post(h.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(f.Encode()))
	if r.StatusCode != 200 {
		t.Fatalf("rotation got %d", r.StatusCode)
	}
	r, _ = http.Post(h.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(f.Encode()))
	if r.StatusCode != 400 {
		t.Fatalf("reused refresh got %d", r.StatusCode)
	}
}

func TestUserInfoRejectsAlgorithmConfusion(t *testing.T) {
	_, h := testServer(t)
	defer h.Close()
	token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"iss": "http://issuer.test", "sub": "normal-user", "exp": timeNow().Add(time.Hour).Unix()})
	raw, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := http.NewRequest(http.MethodGet, h.URL+"/userinfo", nil)
	r.Header.Set("Authorization", "Bearer "+raw)
	resp, _ := http.DefaultClient.Do(r)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("alg=none accepted: %d", resp.StatusCode)
	}
}
