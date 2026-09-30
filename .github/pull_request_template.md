## Summary

## Protocol impact

- [ ] No protocol behavior change
- [ ] OAuth/OIDC behavior change documented
- [ ] Failure scenario change documented

## Verification

- [ ] `go test ./...`
- [ ] `go vet ./...`
- [ ] `go build ./...`
- [ ] `npm --prefix web run lint`
- [ ] `npm --prefix web run build`

## Security review

- [ ] No secrets or full tokens are logged
- [ ] Redirect URI and PKCE behavior remains strict
- [ ] Tests cover invalid input where applicable
