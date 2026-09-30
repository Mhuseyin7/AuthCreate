# Threat model

The primary protected assets are authorization codes, refresh tokens, client secrets, signing keys, and control-plane access. Core mitigations are exact redirect matching, short-lived one-time client-bound codes, mandatory S256 PKCE, RS256-only verification, issuer checks, no full-token event logging, refresh rotation/reuse invalidation, and public-only JWKS.

Out of scope: operating AuthCrate as a public multi-tenant identity provider, real-user credential storage, and MFA delivery. Network attackers and production-grade control-plane hardening require HTTPS, persistent storage, owner authentication, rate limiting, and a deployment secret manager.
