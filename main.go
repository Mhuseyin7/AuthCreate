package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const version = "0.1.0"

type Client struct {
	ID, SecretHash, Name                                     string
	RedirectURIs, PostLogoutRedirectURIs, GrantTypes, Scopes []string
	Public                                                   bool
	AccessTTL, RefreshTTL                                    time.Duration
}
type User struct {
	Subject, Email, Name, Username string
	EmailVerified, Enabled         bool
	Roles, Groups                  []string
	Claims                         map[string]any
}
type Code struct {
	Value, ClientID, RedirectURI, Subject, Scope, Challenge, Nonce string
	Expires                                                        time.Time
	Used                                                           bool
	AuthTime                                                       time.Time
}
type Refresh struct {
	Value, ClientID, Subject, Scope string
	Expires                         time.Time
	Revoked, Used                   bool
}
type Session struct {
	ID, Subject string
	Expires     time.Time
}
type Scenario struct {
	Name, AuthorizationError                           string
	TokenDelay                                         time.Duration
	MFA, ExpireSession, RevokeRefresh, InvalidAudience bool
}
type Event struct {
	At   time.Time         `json:"at"`
	Type string            `json:"type"`
	Data map[string]string `json:"data"`
}
type Server struct {
	mu               sync.Mutex
	issuer           string
	key              *rsa.PrivateKey
	kid              string
	clients          map[string]*Client
	users            map[string]*User
	codes            map[string]*Code
	refresh          map[string]*Refresh
	sessions         map[string]*Session
	events           []Event
	scenario         Scenario
	mode, adminToken string
}

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}
	switch os.Args[1] {
	case "serve", "start":
		serve()
	case "init":
		fmt.Println("AuthCrate initialized. Run: authcrate serve")
	case "doctor":
		fmt.Println(`{"ok":true,"checks":{"signing":"ok","storage":"memory-development"}}`)
	case "users":
		usersCommand(os.Args[2:])
	case "clients":
		clientsCommand(os.Args[2:])
	case "scenario":
		scenarioCommand(os.Args[2:])
	case "keys":
		if len(os.Args) > 2 && os.Args[2] == "rotate" {
			fmt.Println("Keys rotate on server restart in this development build")
		} else {
			usage()
		}
	default:
		usage()
	}
}
func usage() {
	fmt.Fprintln(os.Stderr, "AuthCrate – Authentication sandbox for developers\nCommands: init, serve, users list|create, clients list|create, scenario list|use, keys rotate, doctor")
}
func usersCommand(a []string) {
	if len(a) > 0 && a[0] == "list" {
		fmt.Println("normal-user\nadmin-user\nbanned-user\nunverified-user\nmfa-user\nempty-profile")
	} else {
		fmt.Println("Use the admin API after `authcrate serve` to persist users.")
	}
}
func clientsCommand(a []string) {
	if len(a) > 0 && a[0] == "list" {
		fmt.Println("playground-client (public)")
	} else {
		fmt.Println("Use the admin API after `authcrate serve` to create clients.")
	}
}
func scenarioCommand(a []string) {
	if len(a) > 0 && a[0] == "list" {
		fmt.Println("happy-path\nexpired-session\nmfa-required\nemail-unverified\nrefresh-expired\nscope-denied\nprovider-down\nslow-provider")
	} else {
		fmt.Println("Scenario selection is per running instance; use POST /admin/scenario.")
	}
}

func serve() {
	issuer := os.Getenv("AUTHCRATE_ISSUER")
	if issuer == "" {
		issuer = "http://localhost:8080"
	}
	s, err := newServer(strings.TrimRight(issuer, "/"))
	if err != nil {
		log.Fatal(err)
	}
	s.mode = os.Getenv("AUTHCRATE_MODE")
	if s.mode == "" {
		s.mode = "DEVELOPMENT"
	}
	s.adminToken = os.Getenv("AUTHCRATE_ADMIN_TOKEN")
	if s.mode == "SELF_HOSTED" && (!strings.HasPrefix(issuer, "https://") || len(s.adminToken) < 32) {
		log.Fatal("SELF_HOSTED requires an HTTPS issuer and AUTHCRATE_ADMIN_TOKEN of at least 32 characters")
	}
	addr := ":8080"
	if v := os.Getenv("AUTHCRATE_ADDR"); v != "" {
		addr = v
	}
	log.Printf("AuthCrate %s serving %s (%s)", version, issuer, s.mode)
	log.Fatal(http.ListenAndServe(addr, s.routes()))
}
func newServer(issuer string) (*Server, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	s := &Server{issuer: issuer, key: key, kid: "dev-" + random(6), clients: map[string]*Client{}, users: map[string]*User{}, codes: map[string]*Code{}, refresh: map[string]*Refresh{}, sessions: map[string]*Session{}}
	s.clients["playground-client"] = &Client{ID: "playground-client", Name: "Built-in PKCE playground", RedirectURIs: []string{issuer + "/playground/callback"}, GrantTypes: []string{"authorization_code", "refresh_token"}, Scopes: []string{"openid", "profile", "email", "offline_access"}, Public: true, AccessTTL: 15 * time.Minute, RefreshTTL: 24 * time.Hour}
	s.seed()
	return s, nil
}
func (s *Server) seed() {
	s.users["normal-user"] = &User{"normal-user", "normal@example.test", "Normal User", "normal", true, true, []string{"user"}, nil, map[string]any{}}
	s.users["admin-user"] = &User{"admin-user", "admin@example.test", "Admin User", "admin", true, true, []string{"admin"}, nil, map[string]any{}}
	s.users["banned-user"] = &User{"banned-user", "banned@example.test", "Banned User", "banned", true, false, nil, nil, map[string]any{}}
	s.users["unverified-user"] = &User{"unverified-user", "unverified@example.test", "Unverified User", "unverified", false, true, nil, nil, map[string]any{}}
	s.users["mfa-user"] = &User{"mfa-user", "mfa@example.test", "MFA User", "mfa", true, true, nil, nil, map[string]any{}}
	s.users["empty-profile"] = &User{"empty-profile", "", "", "empty", false, true, nil, nil, map[string]any{}}
}
func (s *Server) routes() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/health", jsonOK)
	m.HandleFunc("/ready", jsonOK)
	m.HandleFunc("/.well-known/openid-configuration", s.discovery)
	m.HandleFunc("/.well-known/jwks.json", s.jwks)
	m.HandleFunc("/authorize", s.authorize)
	m.HandleFunc("/token", s.token)
	m.HandleFunc("/userinfo", s.userinfo)
	m.HandleFunc("/revoke", s.revoke)
	m.HandleFunc("/logout", s.logout)
	m.Handle("/admin/scenario", s.admin(http.HandlerFunc(s.adminScenario)))
	m.Handle("/admin/events", s.admin(http.HandlerFunc(s.adminEvents)))
	m.HandleFunc("/", s.ui)
	return securityHeaders(m)
}
func jsonOK(w http.ResponseWriter, r *http.Request) {
	respond(w, http.StatusOK, map[string]bool{"ok": true})
}
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
func (s *Server) discovery(w http.ResponseWriter, r *http.Request) {
	respond(w, 200, map[string]any{"issuer": s.issuer, "authorization_endpoint": s.issuer + "/authorize", "token_endpoint": s.issuer + "/token", "userinfo_endpoint": s.issuer + "/userinfo", "jwks_uri": s.issuer + "/.well-known/jwks.json", "revocation_endpoint": s.issuer + "/revoke", "end_session_endpoint": s.issuer + "/logout", "response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code", "refresh_token", "client_credentials"}, "code_challenge_methods_supported": []string{"S256"}, "token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"}, "scopes_supported": []string{"openid", "profile", "email", "offline_access"}, "id_token_signing_alg_values_supported": []string{"RS256"}})
}
func (s *Server) jwks(w http.ResponseWriter, r *http.Request) {
	n := base64.RawURLEncoding.EncodeToString(s.key.PublicKey.N.Bytes())
	e := s.key.PublicKey.E
	b := []byte{byte(e >> 16), byte(e >> 8), byte(e)}
	eBytes := []byte(strings.TrimLeft(string(b), "\x00"))
	respond(w, 200, map[string]any{"keys": []map[string]string{{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": s.kid, "n": n, "e": base64.RawURLEncoding.EncodeToString(eBytes)}}})
}
func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	cid, redir := q.Get("client_id"), q.Get("redirect_uri")
	c := s.client(cid)
	if c == nil || !validRedirect(c, redir) {
		oauthErr(w, r, "invalid_request", "unknown client or redirect URI", "")
		return
	}
	if q.Get("response_type") != "code" {
		oauthErr(w, r, "unsupported_response_type", "only code is supported", redir)
		return
	}
	scopes, ok := s.scopes(c, q.Get("scope"))
	if !ok {
		oauthErr(w, r, "invalid_scope", "scope is not allowed", redir)
		return
	}
	if strings.Contains(scopes, "openid") && q.Get("nonce") == "" {
		oauthErr(w, r, "invalid_request", "nonce is required for OpenID Connect", redir)
		return
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		oauthErr(w, r, "invalid_request", "PKCE S256 is required", redir)
		return
	}
	s.mu.Lock()
	scenario := s.scenario
	s.mu.Unlock()
	if scenario.AuthorizationError != "" {
		oauthErr(w, r, scenario.AuthorizationError, "scenario active", redir)
		return
	}
	if scenario.TokenDelay > 0 {
		time.Sleep(scenario.TokenDelay)
	}
	if r.Method == "GET" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, loginHTML(q))
		return
	}
	if err := r.ParseForm(); err != nil {
		oauthErr(w, r, "invalid_request", "invalid form", redir)
		return
	}
	subject := r.Form.Get("user")
	if scenario.MFA && r.Form.Get("mfa") != "123456" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, mfaHTML(q, subject))
		return
	}
	s.mu.Lock()
	user := s.users[subject]
	if user == nil || !user.Enabled {
		s.mu.Unlock()
		oauthErr(w, r, "access_denied", "user disabled or missing", redir)
		return
	}
	if scenario.ExpireSession {
		s.mu.Unlock()
		oauthErr(w, r, "login_required", "session expired by scenario", redir)
		return
	}
	now := time.Now()
	code := random(32)
	sid := random(32)
	s.codes[code] = &Code{code, cid, redir, subject, scopes, q.Get("code_challenge"), q.Get("nonce"), now.Add(60 * time.Second), false, now}
	s.sessions[sid] = &Session{sid, subject, now.Add(8 * time.Hour)}
	s.event("login.success", map[string]string{"subject": subject})
	s.event("authorization.code.issued", map[string]string{"client_id": cid, "subject": subject})
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "authcrate_session", Value: sid, Path: "/", HttpOnly: true, Secure: strings.HasPrefix(s.issuer, "https://"), SameSite: http.SameSiteLaxMode, Expires: now.Add(8 * time.Hour)})
	u, _ := url.Parse(redir)
	v := u.Query()
	v.Set("code", code)
	v.Set("state", q.Get("state"))
	u.RawQuery = v.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}
func loginHTML(q url.Values) string {
	return `<!doctype html><title>AuthCrate login</title><h1>Authenticate with AuthCrate</h1><p>Development identities; no real credentials are used.</p><form method="post"><label>User <select name="user"><option>normal-user</option><option>admin-user</option><option>unverified-user</option><option>mfa-user</option><option>banned-user</option></select></label><button>Continue</button></form>`
}
func mfaHTML(q url.Values, subject string) string {
	return `<h1>MFA Required</h1><p>Development code: <code>123456</code></p><form method="post"><input type="hidden" name="user" value="` + subject + `"><label>Code <input name="mfa" autocomplete="one-time-code"></label><button>Verify</button></form>`
}
func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		respond(w, 405, map[string]string{"error": "method_not_allowed"})
		return
	}
	if err := r.ParseForm(); err != nil {
		tokenErr(w, "invalid_request")
		return
	}
	c := s.authenticateClient(r)
	if c == nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="token"`)
		tokenErr(w, "invalid_client")
		return
	}
	s.mu.Lock()
	scenario := s.scenario
	s.mu.Unlock()
	if scenario.TokenDelay > 0 {
		time.Sleep(scenario.TokenDelay)
	}
	switch r.Form.Get("grant_type") {
	case "authorization_code":
		s.exchangeCode(w, r, c, scenario)
	case "refresh_token":
		s.exchangeRefresh(w, r, c, scenario)
	case "client_credentials":
		s.clientCredentials(w, r, c, scenario)
	default:
		tokenErr(w, "unsupported_grant_type")
	}
}
func (s *Server) exchangeCode(w http.ResponseWriter, r *http.Request, c *Client, sc Scenario) {
	raw := r.Form.Get("code")
	s.mu.Lock()
	code := s.codes[raw]
	if code == nil || code.Used || time.Now().After(code.Expires) || code.ClientID != c.ID || code.RedirectURI != r.Form.Get("redirect_uri") {
		s.mu.Unlock()
		tokenErr(w, "invalid_grant")
		return
	}
	sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
	if r.Form.Get("code_verifier") == "" || base64.RawURLEncoding.EncodeToString(sum[:]) != code.Challenge {
		s.mu.Unlock()
		tokenErr(w, "invalid_grant")
		return
	}
	code.Used = true
	user := s.users[code.Subject]
	s.event("token.exchanged", map[string]string{"client_id": c.ID})
	s.mu.Unlock()
	s.issue(w, c, user, code.Scope, code.Nonce, code.AuthTime, sc)
}
func (s *Server) exchangeRefresh(w http.ResponseWriter, r *http.Request, c *Client, sc Scenario) {
	raw := r.Form.Get("refresh_token")
	s.mu.Lock()
	t := s.refresh[raw]
	if t == nil || t.Used || t.Revoked || time.Now().After(t.Expires) || t.ClientID != c.ID {
		if t != nil {
			t.Revoked = true
			s.event("refresh.reuse_detected", map[string]string{"client_id": c.ID})
		}
		s.mu.Unlock()
		tokenErr(w, "invalid_grant")
		return
	}
	t.Used = true
	if sc.RevokeRefresh {
		t.Revoked = true
		s.mu.Unlock()
		tokenErr(w, "invalid_grant")
		return
	}
	user := s.users[t.Subject]
	scope := t.Scope
	s.event("refresh.rotated", map[string]string{"client_id": c.ID})
	s.mu.Unlock()
	s.issue(w, c, user, scope, "", time.Now(), sc)
}
func (s *Server) clientCredentials(w http.ResponseWriter, r *http.Request, c *Client, sc Scenario) {
	if c.Public {
		tokenErr(w, "unauthorized_client")
		return
	}
	scope, ok := s.scopes(c, r.Form.Get("scope"))
	if !ok {
		tokenErr(w, "invalid_scope")
		return
	}
	s.issue(w, c, nil, scope, "", time.Now(), sc)
}
func (s *Server) issue(w http.ResponseWriter, c *Client, u *User, scope, nonce string, auth time.Time, sc Scenario) {
	now := time.Now()
	aud := c.ID
	if sc.InvalidAudience {
		aud = "wrong-audience"
	}
	claims := jwt.MapClaims{"iss": s.issuer, "aud": aud, "iat": now.Unix(), "exp": now.Add(c.AccessTTL).Unix(), "scope": scope, "client_id": c.ID}
	if u != nil {
		claims["sub"] = u.Subject
	}
	access, err := s.sign(claims)
	if err != nil {
		tokenErr(w, "server_error")
		return
	}
	out := map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": int(c.AccessTTL.Seconds()), "scope": scope}
	if strings.Contains(scope, "openid") && u != nil {
		id := jwt.MapClaims{"iss": s.issuer, "sub": u.Subject, "aud": c.ID, "exp": now.Add(c.AccessTTL).Unix(), "iat": now.Unix(), "auth_time": auth.Unix()}
		if nonce != "" {
			id["nonce"] = nonce
		}
		if strings.Contains(scope, "email") {
			id["email"] = u.Email
			id["email_verified"] = u.EmailVerified
		}
		if strings.Contains(scope, "profile") {
			id["name"] = u.Name
			id["preferred_username"] = u.Username
		}
		tok, _ := s.sign(id)
		out["id_token"] = tok
	}
	if strings.Contains(scope, "offline_access") && u != nil {
		raw := random(32)
		s.mu.Lock()
		s.refresh[raw] = &Refresh{raw, c.ID, u.Subject, scope, now.Add(c.RefreshTTL), false, false}
		s.mu.Unlock()
		out["refresh_token"] = raw
	}
	respond(w, 200, out)
}
func (s *Server) sign(c jwt.MapClaims) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	t.Header["kid"] = s.kid
	return t.SignedString(s.key)
}
func (s *Server) userinfo(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == r.Header.Get("Authorization") {
		respond(w, 401, map[string]string{"error": "invalid_token"})
		return
	}
	parsed, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, errors.New("unexpected signing method")
		}
		return &s.key.PublicKey, nil
	}, jwt.WithIssuer(s.issuer))
	if err != nil || !parsed.Valid {
		respond(w, 401, map[string]string{"error": "invalid_token"})
		return
	}
	claims := parsed.Claims.(jwt.MapClaims)
	sub, _ := claims.GetSubject()
	s.mu.Lock()
	u := s.users[sub]
	s.mu.Unlock()
	if u == nil {
		respond(w, 401, map[string]string{"error": "invalid_token"})
		return
	}
	scope, _ := claims["scope"].(string)
	out := map[string]any{"sub": u.Subject}
	if strings.Contains(scope, "profile") {
		out["name"] = u.Name
		out["preferred_username"] = u.Username
	}
	if strings.Contains(scope, "email") {
		out["email"] = u.Email
		out["email_verified"] = u.EmailVerified
	}
	respond(w, 200, out)
}
func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		respond(w, 405, map[string]string{"error": "method_not_allowed"})
		return
	}
	r.ParseForm()
	c := s.authenticateClient(r)
	if c == nil {
		tokenErr(w, "invalid_client")
		return
	}
	s.mu.Lock()
	if t := s.refresh[r.Form.Get("token")]; t != nil && t.ClientID == c.ID {
		t.Revoked = true
		s.event("token.revoked", map[string]string{"client_id": c.ID})
	}
	s.mu.Unlock()
	w.WriteHeader(200)
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("authcrate_session"); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "authcrate_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: strings.HasPrefix(s.issuer, "https://"), SameSite: http.SameSiteLaxMode})
	s.event("logout", map[string]string{})
	target := r.URL.Query().Get("post_logout_redirect_uri")
	if target != "" {
		for _, c := range s.clients {
			if contains(c.PostLogoutRedirectURIs, target) {
				http.Redirect(w, r, target, 302)
				return
			}
		}
	}
	w.WriteHeader(204)
}
func (s *Server) adminScenario(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		s.mu.Lock()
		defer s.mu.Unlock()
		respond(w, 200, s.scenario)
		return
	}
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	var x struct {
		Name string `json:"name"`
	}
	if json.NewDecoder(r.Body).Decode(&x) != nil {
		respond(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	sc := scenario(x.Name)
	s.mu.Lock()
	s.scenario = sc
	s.event("scenario.used", map[string]string{"name": x.Name})
	s.mu.Unlock()
	respond(w, 200, sc)
}
func scenario(n string) Scenario {
	switch n {
	case "mfa-required":
		return Scenario{Name: n, MFA: true}
	case "expired-session":
		return Scenario{Name: n, ExpireSession: true}
	case "scope-denied":
		return Scenario{Name: n, AuthorizationError: "invalid_scope"}
	case "provider-down":
		return Scenario{Name: n, AuthorizationError: "temporarily_unavailable"}
	case "slow-provider":
		return Scenario{Name: n, TokenDelay: 2 * time.Second}
	case "refresh-expired":
		return Scenario{Name: n, RevokeRefresh: true}
	default:
		return Scenario{Name: "happy-path"}
	}
}
func (s *Server) adminEvents(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	respond(w, 200, s.events)
}
func (s *Server) ui(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/assets/") {
		http.ServeFile(w, r, "web/dist"+r.URL.Path)
		return
	}
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if _, err := os.Stat("web/dist/index.html"); err == nil {
		http.ServeFile(w, r, "web/dist/index.html")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.WriteString(w, `<!doctype html><title>AuthCrate</title><h1>AuthCrate</h1><p>Control-plane assets are not built. Run <code>npm --prefix web install && npm --prefix web run build</code>.</p>`)
}
func (s *Server) authenticateClient(r *http.Request) *Client {
	id, sec, ok := r.BasicAuth()
	if !ok {
		id = r.Form.Get("client_id")
		sec = r.Form.Get("client_secret")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.clients[id]
	if c == nil {
		return nil
	}
	if c.Public {
		if sec != "" {
			return nil
		}
		return c
	}
	if c.SecretHash == "" || secretHash(sec) != c.SecretHash {
		return nil
	}
	return c
}
func (s *Server) client(id string) *Client { s.mu.Lock(); defer s.mu.Unlock(); return s.clients[id] }
func (s *Server) scopes(c *Client, v string) (string, bool) {
	if v == "" {
		v = "openid"
	}
	for _, x := range strings.Fields(v) {
		if !contains(c.Scopes, x) {
			return "", false
		}
	}
	return v, true
}
func (s *Server) event(t string, d map[string]string) {
	s.events = append(s.events, Event{time.Now(), t, d})
	if len(s.events) > 1000 {
		s.events = s.events[len(s.events)-1000:]
	}
}
func validRedirect(c *Client, v string) bool { return contains(c.RedirectURIs, v) }
func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
func secretHash(v string) string { x := sha256.Sum256([]byte(v)); return hex.EncodeToString(x[:]) }
func random(n int) string {
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func oauthErr(w http.ResponseWriter, r *http.Request, code, desc, redir string) {
	if redir != "" {
		u, _ := url.Parse(redir)
		q := u.Query()
		q.Set("error", code)
		q.Set("error_description", desc)
		if st := r.URL.Query().Get("state"); st != "" {
			q.Set("state", st)
		}
		u.RawQuery = q.Encode()
		http.Redirect(w, r, u.String(), 302)
		return
	}
	respond(w, 400, map[string]string{"error": code, "error_description": desc})
}
func tokenErr(w http.ResponseWriter, e string) { respond(w, 400, map[string]string{"error": e}) }
func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func publicPEM(k *rsa.PrivateKey) string {
	b := x509.MarshalPKCS1PublicKey(&k.PublicKey)
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: b}))
}
