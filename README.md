# AuthCrate

[![CI](https://github.com/Mhuseyin7/AuthCreate/actions/workflows/ci.yml/badge.svg)](https://github.com/Mhuseyin7/AuthCreate/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

### Authentication sandbox for developers

AuthCrate, **muhammedkoca.com.tr tarafından geliştirilmiş open-source bir developer authentication sandbox’ıdır.** Local development, automated testing, OAuth/OIDC debugging ve controlled failure simulation için gerçek protocol davranışı sağlar.

> AuthCrate bir fake login-page demo, production IAM platformu veya Auth0/Keycloak replacement değildir.

## Quick start

Go 1.24+ ile:

```bash
git clone https://github.com/Mhuseyin7/AuthCreate.git
cd AuthCreate
go run . serve
```

Docker Compose ile:

```bash
docker compose up --build
```

Server varsayılan olarak `http://localhost:8080` adresinde çalışır. Discovery metadata:
`http://localhost:8080/.well-known/openid-configuration`

Built-in public test client:

```text
client_id:    playground-client
redirect_uri: http://localhost:8080/playground/callback
```

## AuthCrate nedir?

Gerçek bir Google, GitHub veya enterprise identity provider’a ihtiyaç duymadan uygulamanızın authentication davranışını test etmenizi sağlar. Deterministic fixture identities ve scenario presets ile normal flow’ları ve failure durumlarını tekrar tekrar çalıştırabilirsiniz.

AuthCrate bir fake login-page demo, production IAM platformu veya Auth0/Keycloak replacement değildir.

## Implemented protocol surface

- OpenID Connect Discovery
- Authorization Code Flow
- PKCE with mandatory `S256`
- Exact redirect URI validation
- RS256 signed access tokens and ID tokens
- JWKS with `kid`
- UserInfo endpoint
- Refresh token rotation and reuse detection
- Refresh token revocation
- End-session / logout
- OAuth client credentials flow
- Secure HttpOnly login session cookie
- Issuer, audience, expiry and nonce claims

Authorization codes 60 seconds geçerlidir; single-use’dir ve client, redirect URI ile PKCE challenge’a bağlıdır. Password grant intentionally desteklenmez.

## OIDC integration

Uygulamanız endpoint URL’lerini hard-code etmek yerine discovery document’ı okumalıdır:

```bash
curl http://localhost:8080/.well-known/openid-configuration
curl http://localhost:8080/.well-known/jwks.json
```

Authorization request şu parametreleri içermelidir:

```text
response_type=code
client_id=playground-client
redirect_uri=http://localhost:8080/playground/callback
scope=openid profile email offline_access
state=<random-state>
nonce=<random-nonce>
code_challenge=<base64url-sha256-verifier>
code_challenge_method=S256
```

Callback’teki code’u aynı redirect URI ve original `code_verifier` ile `/token` endpoint’inde exchange edin. ID token’ı JWKS public key ile verify edin; `iss`, `aud`, `exp`, `iat` ve `nonce` kontrollerini atlamayın. Detaylar için [OIDC.md](OIDC.md).

## Built-in identities

```text
normal-user       Enabled, verified email
admin-user        Admin role fixture
banned-user       Disabled identity
unverified-user   email_verified=false
mfa-user          MFA scenario fixture
empty-profile     Minimal profile claims
```

Bunlar gerçek kullanıcı değildir ve gerçek credentials içermez.

## Failure scenarios

Scenario engine gerçek endpoint davranışını değiştirir; yalnızca UI state değiştirmez:

```bash
curl -X POST http://localhost:8080/admin/scenario \
  -H 'Content-Type: application/json' \
  -d '{"name":"mfa-required"}'
```

Preset’ler: `happy-path`, `expired-session`, `mfa-required`, `scope-denied`, `provider-down`, `slow-provider`, `refresh-expired`.

MFA development code: `123456`.

## React control panel

`web/` altında React + TypeScript strict mode + Tailwind CSS ile hazırlanmış control panel bulunur. Panel discovery metadata’yı, active scenario’yu ve protocol events’i gerçek AuthCrate endpoint’lerinden okur.

```bash
npm --prefix web install
npm --prefix web run lint
npm --prefix web run build
```

Docker image build sırasında frontend otomatik olarak compile edilir.

## Security modes

Self-hosted deployment için:

```bash
AUTHCRATE_MODE=SELF_HOSTED
AUTHCRATE_ISSUER=https://auth.example.test
AUTHCRATE_ADMIN_TOKEN=<at-least-32-random-characters>
```

Self-hosted mode HTTPS issuer, separate control-plane credential ve same-origin checks gerektirir. Signing private key, client secret veya full token event log’larına yazılmaz. AuthCrate’i public internet üzerinde development defaults ile çalıştırmayın.

## Health and verification

```text
GET /health
GET /ready
```

```bash
gofmt -w *.go
go mod tidy
go test ./...
go vet ./...
go build ./...
```

Test suite discovery consistency, redirect validation, PKCE failure/replay, refresh rotation/reuse ve JWT algorithm confusion rejection kontrollerini içerir.

## Documentation

- [OIDC integration guide](OIDC.md)
- [Scenario reference](SCENARIOS.md)
- [Architecture](ARCHITECTURE.md)
- [Threat model](THREAT_MODEL.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)

## Open-source attribution

AuthCrate open-source olarak **muhammedkoca.com.tr tarafından geliştirilir**.

- Website: [muhammedkoca.com.tr](https://muhammedkoca.com.tr)
- Repository: [github.com/Mhuseyin7/AuthCreate](https://github.com/Mhuseyin7/AuthCreate)
- License: [MIT](LICENSE)

Pull request, issue ve security report katkılarına açığız. Security bildirimi için [SECURITY.md](SECURITY.md) sürecini izleyin.

## License

MIT License. Copyright © 2026 AuthCrate contributors / muhammedkoca.com.tr.

