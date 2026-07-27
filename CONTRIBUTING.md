# Contributing

Thanks for taking the time. Bug reports, scanner-format support, and prompt
improvements are all welcome.

## Reporting bugs

Open an issue with the version (`xpsd -version` or the image tag), the full
command line or workflow inputs, and the relevant log output from a `-v` run.
For a wrong verdict, include the scan report entry and the verdict JSON.

Do not report security issues here. See [SECURITY.md](SECURITY.md).

## Development setup

You need Go 1.25+ and Docker.

```sh
make build     # native binaries into build/
make docker    # the all-in-one image (xpsd:latest)
make fmt vet test
```

The repository has two Go modules: `cmd/xpsd` (the CLI) and
`tools/mcp-server/src` (the analysis tool server). `make` targets run in both.
See [docs/build.md](docs/build.md) for details.

## Before you open a pull request

- `make fmt vet test` passes.
- New behaviour has a test. Scanner-format changes need a fixture under
  `cmd/xpsd/testdata/scans/`.
- Flags, action inputs, and their documentation stay in sync: a new flag needs
  wiring in `action.yml`, `docker-entrypoint.sh`, the `xpsd` launcher's help,
  and [docs/usage.md](docs/usage.md) or
  [docs/github-actions.md](docs/github-actions.md).
- Keep the change scoped to one thing. Unrelated reformatting makes review
  harder.

## Code style

- Standard Go formatting (`gofmt`). No extra linter config.
- Types, constants, and structs go at the top of a file; functions below them.
- Comments explain what the code does or why a non-obvious choice was made.
  No commentary on the development process.
- Every source file carries an SPDX header:

  ```go
  // SPDX-License-Identifier: Apache-2.0
  // Copyright 2026 ByteRay Ltd.
  ```

  New files by other contributors should use their own copyright line.

## Licensing

By contributing you agree that your contribution is licensed under the Apache
License 2.0, the same as the project.
