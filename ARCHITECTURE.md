# Architecture

`net/http` hosts the OIDC control and protocol plane. `Server` owns clients, users, authorization codes, refresh-token state, login sessions, event history, scenario state, and the current RSA signing key. Tokens are signed with `github.com/golang-jwt/jwt/v5`; no cryptographic primitive is implemented in application code. Private key material never leaves process memory; only the public JWK is exposed.

The control plane is separate from issued fixture identities. `SELF_HOSTED` mode requires an HTTPS issuer and an independently supplied `AUTHCRATE_ADMIN_TOKEN`; its mutating requests also enforce same-origin checks. The React/Tailwind UI is a real client of the control-plane endpoints and is compiled into the container image.

The current storage adapter is intentionally in-memory for disposable local fixtures. Before operating in a durable self-hosted environment, replace it with the repository abstraction and migrations described in `migrations/`; persistence, owner bootstrap, and control-plane authentication must be configured as a deployment unit.
