# Contributing

Run `gofmt -w .`, `go test ./...`, `go vet ./...`, and `go build ./...` before opening a pull request. Protocol changes need negative tests for malformed input and replay/bypass attempts. Never add a redirect wildcard, password grant, plaintext secret, private-key endpoint, or full-token log.
