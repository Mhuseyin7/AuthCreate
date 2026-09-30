# OIDC integration

Fetch discovery metadata rather than assembling endpoint URLs. Register an exact redirect URI, generate a high-entropy PKCE verifier, and derive an S256 challenge. Send `response_type=code`, `scope=openid profile email offline_access`, `state`, `nonce`, `code_challenge`, and `code_challenge_method=S256` to `/authorize`.

Exchange the callback code at `/token` with the identical redirect URI and verifier. Validate JWT signature against JWKS, issuer, audience, time claims, and nonce in your application. Call `/userinfo` using the access token. Refresh tokens rotate: immediately replace stored refresh material with the returned token. `POST /revoke` accepts the client-authenticated refresh token and always returns 200 for valid client authentication.

Public clients use `client_id` and PKCE without a secret. Confidential clients use HTTP Basic or `client_secret_post`. Never place a client secret in a browser.
