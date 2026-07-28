# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 ByteRay Ltd.

# Stage 1: build Go binaries
FROM golang:1.25-bookworm AS builder

ARG VERSION=dev

WORKDIR /src
COPY cmd/xpsd/           ./cmd/xpsd/
COPY tools/mcp-server/   ./tools/mcp-server/

RUN  cd tools/mcp-server/src && CGO_ENABLED=0 go build -o /out/mcp . \
  && cd /src/cmd/xpsd        && CGO_ENABLED=0 go build -ldflags "-X main.buildVersion=${VERSION}" -o /out/xpsd .

# Stage 2: runtime
FROM node:26-bookworm-slim

ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip \
      git grep ca-certificates \
    && pip3 install --no-cache-dir --break-system-packages playwright beautifulsoup4 \
    && playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/* \
    && chmod -R a+rX /ms-playwright \
    # copilot CLI pinned: the Go SDK (see cmd/xpsd/go.mod) speaks a versioned
    # protocol and older/newer CLIs can break the handshake. Bump both together.
    && npm install -g @ast-grep/cli @github/copilot@1.0.70 \
    # Point /usr/local/bin/copilot at the platform-native binary; the npm bin
    # shim stays in place on architectures without a bundled binary package.
    && arch="$(dpkg --print-architecture)" \
    && case "$arch" in amd64) pkg=copilot-linux-x64 ;; arm64) pkg=copilot-linux-arm64 ;; *) pkg= ;; esac \
    && if [ -n "$pkg" ] && [ -x "/usr/local/lib/node_modules/@github/copilot/node_modules/@github/${pkg}/copilot" ]; then \
         ln -sf "/usr/local/lib/node_modules/@github/copilot/node_modules/@github/${pkg}/copilot" /usr/local/bin/copilot; \
       fi

COPY --from=builder /out/mcp           /usr/local/bin/mcp
COPY --from=builder /out/xpsd          /usr/local/bin/xpsd
COPY tools/web-fetcher/server.py       /opt/web-fetcher/server.py
COPY docker-entrypoint.sh              /usr/local/bin/docker-entrypoint.sh
RUN  chmod +x /usr/local/bin/docker-entrypoint.sh

WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
