# Security policy

## Reporting a vulnerability

Report security issues privately. Do not open a public issue.

- Preferred: [open a private security advisory](https://github.com/ByteRay-AI/xpsd/security/advisories/new)
- Email: security@byteray.co.uk

Please include the version or commit, the command line or workflow inputs used,
and enough detail to reproduce. We will acknowledge within 5 working days and
keep you informed until the issue is resolved.

## Supported versions

Fixes go into the latest release. There are no maintained release branches.

## Threat model

Xpsd runs an LLM agent against a source tree and untrusted vulnerability data.
The trust boundaries that matter:

- **The analyzed source tree** is untrusted. It is mounted read-only, and all
  source access goes through the MCP server, which confines every path to the
  source root (symlinks that point outside degrade to the root).
- **Scan reports, advisory text, fetched web pages, and fetched dependency
  source** are untrusted. Any of them can contain text aimed at the model.
- **Outbound network access** is untrusted in both directions: a target URL may
  be chosen by the model based on that untrusted content.

Outbound fetches that the model can steer go through a single loopback
validating proxy. It resolves each target once and dials that exact address,
and refuses any address that is not globally routable. This blocks SSRF to
loopback, RFC1918, and link-local ranges (including cloud metadata endpoints),
and closes DNS rebinding and redirect chains. `git` traffic is routed through
the same proxy; the web fetcher additionally re-checks every browser request
and the actual server address of every response.

## Known limitations

These are known and documented.

### Prompt injection can bias a verdict

The agent reads untrusted content. An instruction embedded in an advisory, a
web page, or third-party source can influence the verdict it produces. Tool
abuse is contained by the guards above, but verdict integrity is not. A false
`reachable: no` will close a code-scanning alert, so do not treat "not
reachable" as authoritative for high-impact decisions.

### `run_python` is a code-execution surface

The `run_python` MCP tool is **disabled by default**. Enabling it
(`XPSD_ENABLE_RUN_PYTHON=1`) lets the model execute arbitrary Python, which
bypasses the network proxy and reads the filesystem without confinement. Its
network is isolated with `unshare -r -n` where unprivileged user namespaces are
available; the stock container's seccomp profile blocks `unshare`, so there it
runs without isolation. If you enable it, restrict the container's egress
yourself.

### Secrets in the analysis environment

The agent's tool results are logged. Do not point Xpsd at a tree containing
credentials you would not want in the run artifacts, and do not pass API keys
through `guidance`.
