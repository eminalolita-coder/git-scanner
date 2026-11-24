BINARY := git-scanner
PKG    := ./...
VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build test vet fmt lint tidy run clean release

all: build

build:
	go build -ldflags="$(LDFLAGS)" -o $(BINARY) ./cmd/git-scanner

run: build
	./$(BINARY) $(ARGS)

test:
	go test -race ./...

vet:
	go vet $(PKG)

fmt:
	gofmt -s -w .

tidy:
	go mod tidy

lint: vet
	@command -v staticcheck >/dev/null 2>&1 && staticcheck $(PKG) || echo "staticcheck not installed, skipping"

clean:
	rm -f $(BINARY) $(BINARY).exe
	rm -rf dist bin hits

release:
	goreleaser release --clean
