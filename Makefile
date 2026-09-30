.PHONY: fmt test vet build docker

fmt:
	gofmt -w *.go

test:
	go test ./...

vet:
	go vet ./...

build:
	go build ./...

docker:
	docker compose up --build
