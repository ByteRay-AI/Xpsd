# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 ByteRay Ltd.

.PHONY: all build docker tidy fmt vet test clean

# Match only x.y.z tags so the moving major tag (v1) is not picked, and drop the
# leading "v" to match what CI stamps from the release tag.
VERSION ?= $(shell git describe --tags --always --dirty --match 'v[0-9]*.[0-9]*.[0-9]*' 2>/dev/null | sed 's/^v//' || echo dev)
LDFLAGS  = -ldflags "-X main.buildVersion=$(VERSION)"

all: docker

# Native binaries (for development): build/mcp, build/xpsd.
build:
	mkdir -p build
	cd tools/mcp-server/src && go build -o ../../../build/mcp .
	cd cmd/xpsd && go build $(LDFLAGS) -o ../../build/xpsd .

# Build the all-in-one Docker image (Go binaries + ast-grep + python3 + Chromium).
# Source is mounted read-only at runtime; see docker-entrypoint.sh.
docker:
	docker build --build-arg VERSION=$(VERSION) -t xpsd:latest .

tidy:
	cd tools/mcp-server/src && go mod tidy
	cd cmd/xpsd && go mod tidy

fmt:
	cd tools/mcp-server/src && gofmt -l .
	cd cmd/xpsd && gofmt -l .
	@test -z "$$(cd tools/mcp-server/src && gofmt -l .)$$(cd cmd/xpsd && gofmt -l .)" || \
		{ echo "gofmt: files above need formatting"; exit 1; }

vet:
	cd tools/mcp-server/src && go vet ./...
	cd cmd/xpsd && go vet ./...

test:
	cd tools/mcp-server/src && go test -race ./...
	cd cmd/xpsd && go test -race ./...

clean:
	rm -rf build
