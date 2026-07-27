# Building Xpsd

## Docker (recommended)

```sh
make docker          # builds the self-contained image
```

The image carries everything the analysis needs: the `xpsd` binary, the MCP
tool server, `ast-grep`, `python3`, a pinned GitHub Copilot CLI, and the
web-fetcher (headless Chromium behind the `fetch_url` tool).

The `./xpsd` wrapper builds the image on first run, then runs the analysis
inside the container with the source tree mounted read-only:

```sh
./xpsd -source /path/to/project -cve "CVE-2024-45337"
```

The wrapper also mounts `-cve-file`, `-scan`, and `-guidance` files, rewrites
`-sarif-out` into the mounted output directory, and passes credentials through:
`GH_TOKEN` (defaulting to `gh auth token`) for Copilot, and
`OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `AZURE_OPENAI_KEY` for BYOK.

Force a rebuild with `XPSD_REBUILD=1 ./xpsd ...`.

## Native (for development)

Requires Go 1.25+, `ast-grep`, and `python3`:

```sh
make build           # builds build/mcp, build/xpsd
make test            # unit tests, including SARIF schema validation
```

Running the binary directly needs `-mcp-bin` pointing at the MCP server:

```sh
./build/xpsd -mcp-bin ./build/mcp -source /path/to/project -scan scan.json
```

The Copilot CLI version matters. The SDK speaks a versioned protocol.
The image pins a known-good version; for native runs, point `COPILOT_CLI_PATH`
at the same one:

```sh
npm install -g @github/copilot@1.0.70
```

When bumping the SDK in `cmd/xpsd/go.mod`, bump the CLI pin in the `Dockerfile`
together with it.

## Repository layout

| Path | Contents |
|------|----------|
| `cmd/xpsd/` | the CLI: scan parsing, filtering, agent loop, SARIF output |
| `tools/mcp-server/src/` | MCP tool server (file tools, ast-grep, OSV, dependency fetch) |
| `tools/web-fetcher/` | headless Chromium service behind `fetch_url` |
| `action.yml`, `docker-entrypoint.sh` | GitHub Action packaging |
| `xpsd` | host wrapper that runs the image |

## Releasing

Releases are driven by tags. Pushing an `x.y.z` tag runs
[.github/workflows/publish.yml](../.github/workflows/publish.yml), which builds
the image and pushes it to GHCR as `1.2.3`, `1.2`, and `1`.

```sh
git tag -a v1.2.3 -m v1.2.3
git push origin v1.2.3
```

Then move the major tag, so `uses: byteray-ai/xpsd@v1` picks up the new
`action.yml`:

```sh
git tag -f v1 -m v1
git push -f origin v1
```

Only `v[0-9]+.[0-9]+.[0-9]+` tags publish. A moving tag like `v1` produces no
semver image tags, so pushing it alone would fail the build rather than release
anything. The image reference inside `action.yml` is the floating `:1` tag, so a
patch release reaches existing `@v1` users as soon as the image is pushed.

The version compiled into the binary comes from the tag: CI passes the semver
version as a build arg, and local builds derive it from `git describe`. Check it
with `xpsd -version`.
