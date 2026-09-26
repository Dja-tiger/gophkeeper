VERSION ?= dev
DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
COMMIT := $(shell git rev-parse --short HEAD)
LDFLAGS := -X github.com/Dja-tiger/gophkeeper/internal/buildinfo.Version=$(VERSION) -X github.com/Dja-tiger/gophkeeper/internal/buildinfo.Date=$(DATE) -X github.com/Dja-tiger/gophkeeper/internal/buildinfo.Commit=$(COMMIT)

.PHONY: build test check integration release docs security
build:
	mkdir -p bin
	go build -trimpath -ldflags '$(LDFLAGS)' -o bin/gophkeeper ./cmd/client
	go build -trimpath -ldflags '$(LDFLAGS)' -o bin/gophkeeper-server ./cmd/server

test:
	go test -race -coverpkg=./... -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1
	go tool cover -func=coverage.out | awk '/^total:/ {gsub(/%/, "", $$3); if ($$3 < 70) exit 1}'

docs:
	go run scripts/check-docs.go

check: docs
	test -z "$$(gofmt -l cmd internal scripts)"
	go vet ./...
	$(MAKE) test

integration:
	@test -n "$(GOPHKEEPER_TEST_DATABASE_URL)" || (echo 'Set GOPHKEEPER_TEST_DATABASE_URL to a disposable database'; exit 1)
	go test -race -tags=integration ./...

release:
	@mkdir -p bin
	@for os in linux darwin windows; do for arch in amd64 arm64; do \
	 ext=""; if [ "$$os" = windows ]; then ext=.exe; fi; \
	 CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags '$(LDFLAGS)' -o bin/gophkeeper-$$os-$$arch$$ext ./cmd/client || exit 1; \
	 done; done

security:
	go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
