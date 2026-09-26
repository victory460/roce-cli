GO ?= go
VERSION ?= dev
LDFLAGS = -s -w -X main.version=$(VERSION)

.PHONY: build test race vet check cross examples
build:
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/roce-cli .
test:
	$(GO) test ./...
race:
	$(GO) test -race ./...
vet:
	$(GO) vet ./...
check: test race vet
cross:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/roce-cli-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/roce-cli-linux-arm64 .
examples: build
	python3 scripts/verify_examples.py ./bin/roce-cli
