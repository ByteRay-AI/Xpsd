# Xpsd in GitHub Actions

Xpsd ships as a container action. It reads a scanner report, judges each
finding against your source, and writes SARIF that
`github/codeql-action/upload-sarif` turns into code scanning alerts.

```
checkout -> SBOM -> scanner -> xpsd (reachability) -> SARIF -> Security tab
```

## Prerequisites

**Code scanning must be available.** Free on public repos; private repos need
GitHub Advanced Security.

**The job needs permissions:**

```yaml
permissions:
  contents: read
  security-events: write   # upload-sarif
  copilot-requests: write  # only for the built-in-token Copilot path
```

## Model access

Pick one. This is the only part that needs setup.

**Copilot with the built-in token.** Grant `copilot-requests: write` and the
default `github.token` authenticates Copilot, so there is no secret. The org
needs the "Allow use of Copilot CLI billed to the organization" policy enabled,
on by default if the Copilot CLI policy is on, and AI credits bill to the org.
This is documented for organization-owned repositories; on a personal repo the
built-in token may not carry Copilot access.

**Copilot with a PAT.** Pass `github-token: ${{ secrets.COPILOT_PAT }}`, where
`COPILOT_PAT` is a fine-grained PAT with the Copilot Requests permission owned
by a user with a Copilot seat. Use this when the built-in token cannot reach
Copilot.

**BYOK.** Set `provider-type`, `api-key`, and a matching `model`. No Copilot
involved, and you can drop `copilot-requests` from `permissions`.

```yaml
provider-type: anthropic
api-key: ${{ secrets.ANTHROPIC_API_KEY }}
model: claude-sonnet-4-6
```

## A working workflow

```yaml
name: reachability
on:
  workflow_dispatch:
  schedule:
    - cron: "0 6 * * 1"

permissions:
  contents: read
  security-events: write
  copilot-requests: write

jobs:
  reachability:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: anchore/sbom-action@v0
        with:
          format: cyclonedx-json
          output-file: sbom.cdx.json
          upload-artifact: false

      # output-file must be workspace-relative. Without it, scan-action writes
      # to the runner's temp dir, which the Xpsd container cannot see.
      - uses: anchore/scan-action@v6
        with:
          sbom: sbom.cdx.json
          output-format: json
          output-file: scan.json
          fail-build: false

      - uses: byteray-ai/xpsd@v1
        id: xpsd
        with:
          scan-file: scan.json
          model: gpt-5.3-codex
          min-severity: medium
          max-findings: "10"

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: ${{ steps.xpsd.outputs.sarif-file }}
          category: xpsd-reachability

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: xpsd-results
          path: xpsd-results/xpsd
```

Any file the action reads must be workspace-relative, because the container
only sees the checkout. That applies to `scan-file`, `cve-file`, and
`guidance-file`.

## Scanner variants

Any of these produce a report Xpsd accepts; the format is auto-detected.

```yaml
# Trivy
- uses: aquasecurity/trivy-action@0.28.0
  with: {scan-type: fs, format: json, output: scan.json, scan-ref: .}

# OSV-Scanner (scans the SBOM directly)
- run: |
    curl -sSfLo osv-scanner https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64
    chmod +x osv-scanner
    ./osv-scanner --sbom=sbom.cdx.json --format json > scan.json || true
# osv-scanner exits nonzero when it finds vulns; `|| true` keeps the step green

# Snyk
- uses: snyk/actions/node@master
  continue-on-error: true
  env: {SNYK_TOKEN: "${{ secrets.SNYK_TOKEN }}"}
  with: {args: --json-file-output=scan.json}
```

## Pinning a version

```yaml
uses: byteray-ai/xpsd@v1        # latest 1.x, moves when a release is cut
uses: byteray-ai/xpsd@v1.0.0    # exactly the code released as 1.0.0
```

A version ref pins the code, not just the input list. `action.yml` at each
release tag names that release's container image, so `@v1.0.0` keeps running
1.0.0 after 1.1.0 ships. `@v1` follows releases.

## Inputs

Exactly one of `scan-file`, `cve`, or `cve-file` is required, plus `model`.

Everything under Filtering applies to scan mode only. In `cve` / `cve-file`
mode there is a single finding to analyze, so those inputs are ignored and the
step logs a warning naming them.

### What to analyze

| Input | Default | Meaning |
|-------|---------|---------|
| `scan-file` | (none) | scanner report to analyze, workspace-relative |
| `scan-format` | `auto` | `grype` \| `trivy` \| `osv` \| `snyk` \| `sarif` |
| `cve` | (none) | vulnerability description text (single-CVE mode) |
| `cve-file` | (none) | same, read from a workspace file |
| `source` | `.` | directory to analyze, relative to the repo root |

### Filtering

| Input | Default | Meaning |
|-------|---------|---------|
| `min-severity` | (none) | skip findings below `low`/`medium`/`high`/`critical` |
| `min-cvss` | (none) | skip findings with a CVSS base score below this (0-10) |
| `max-findings` | `0` | analyze at most N, highest severity first (0 = all) |
| `only` | (none) | comma-separated CVE/GHSA ids; aliases match too |
| `is-remote` | `false` | only findings shown to be network-reachable (CVSS `AV:N`); no vector means dropped |
| `is-exploited` | `false` | only findings listed as exploited in CVSS-BT; not listed means dropped |
| `no-enrich` | `false` | disable OSV lookup of missing severity, CVSS, and vector |

The pipeline runs dedup, then `only`, then OSV enrichment (plain HTTP lookups,
not LLM calls), then the remaining filters, then the `max-findings` cap. All
conditions are ANDed. `only` comes before enrichment because an explicit id list
needs no enriched data. Because every filter runs before analysis and the cap
runs last, no LLM session is spent on a finding a filter would drop, and
`max-findings: "10"` means ten findings analyzed.

The two exploitability gates need positive evidence: a finding with no CVSS
vector cannot be shown remote, and a CVE with no CVSS-BT entry cannot be shown
exploited, so either way it is dropped. The severity and CVSS floors work the
other way and keep unscored findings, since a missing score is not a low score.

If the CVSS-BT download fails outright, `is-exploited` fails the step instead of
dropping every finding and reporting an empty run as though nothing qualified.

`is-exploited` uses the [CVSS-BT](https://github.com/t0sche/cvss-bt) dataset
(CISA KEV, VulnCheck KEV, ExploitDB, Metasploit, Nuclei, or a GitHub PoC). It
downloads roughly 80 MB, streamed, and only when the input is set.

### Project context

| Input | Default | Meaning |
|-------|---------|---------|
| `guidance` | (none) | authoritative project facts as free text |
| `guidance-file` | (none) | same, read from a workspace file; used when `guidance` is empty |

```yaml
          guidance: |
            The admin API is reachable only from the internal network.
            libfoo is vendored but never compiled into the shipped image.
```

### Model

| Input | Default | Meaning |
|-------|---------|---------|
| `model` | required | model id, for example `gpt-5.3-codex` |
| `effort` | provider default | `low` \| `medium` \| `high` \| `xhigh` |
| `github-token` | `github.token` | token for Copilot auth |
| `provider-type` | (none) | BYOK: `openai` \| `anthropic` \| `azure` |
| `base-url` | (none) | BYOK endpoint |
| `api-key` | (none) | BYOK key; pass a secret |

### Budgets and output

| Input | Default | Meaning |
|-------|---------|---------|
| `max-cycles` | `50` | tool-call budget per finding |
| `max-tokens` | `0` | context-token budget per finding (0 = unlimited) |
| `adversary-cycles` | `15` | tool-call budget for the adversarial review pass that re-checks each decisive verdict (0 = off) |
| `adversary-tokens` | `0` | context-token budget for that pass (0 = unlimited) |
| `out-dir` | `xpsd-results` | output dir; SARIF at `<out-dir>/xpsd/results.sarif` |
| `fail-on` | (none) | fail the step on `reachable`, or on `uncertain` for the stricter gate |
| `no-markdown` | `true` | skip per-finding markdown reports; `false` renders them |
| `no-web` | `false` | disable the `fetch_url` tool |
| `verbose` | `false` | progress logs: tool discovery, each tool call, and the CLI's own debug log. Off by default, so the step prints only the verdict summary |

`max-cycles` and `max-tokens` are both per-finding ceilings, and whichever is
reached first stops further tool calls and asks the model to answer from what it
has. Set `max-tokens` when a model with a large context makes the cycle count a
poor proxy for spend.

## Outputs

| Output | Meaning |
|--------|---------|
| `sarif-file` | path to the SARIF file, workspace-relative |
| `reachable` | `yes` when anything is reachable, else `no` |
| `reachable-count` | number of findings judged reachable (scan mode) |

```yaml
      - if: steps.xpsd.outputs.reachable == 'yes'
        run: echo "${{ steps.xpsd.outputs.reachable-count }} reachable finding(s)"
```

`fail-on` exits the step with code 2 while still writing outputs and SARIF, so
a later `if: always()` upload step still runs.

## Reading the alerts

| Verdict | SARIF level | `security-severity` | Shown as |
|---------|-------------|---------------------|----------|
| reachable (medium/high confidence) | `error` | the CVSS score | its real severity |
| reachable (low confidence), uncertain, analysis failed | `warning` | the CVSS score | its real severity, needs manual review |
| not reachable | `note` | `1.0` | low, informational |

A ruled-out finding drops to the low band on purpose. GitHub buckets alerts by
`security-severity` alone (over 9.0 critical, 7.0 to 8.9 high, 4.0 to 6.9 medium,
0.1 to 3.9 low) and ignores the SARIF level when deciding severity, so leaving a
ruled-out CVSS 9.8 at 9.8 files it as Critical no matter what the level says.
That is what buries the findings that are actually reachable. The vulnerability's
own rating is unchanged and still appears in the rule description, and the alert
body carries the verdict, the reasoning, and the evidence.

Two things are never downgraded: an `uncertain` verdict and a finding that
errored or produced unparseable output. Both are unreviewed and keep their real
severity.

`security-severity` is a property of the SARIF *rule*, not the result, and one
rule covers one vulnerability id. When the same id is analyzed for several
packages and the verdicts differ, the rule takes the most serious outcome, so a
single reachable finding keeps the whole rule at its real severity while each
result keeps its own level.

The alert body carries the verdict, the model's rationale, and the call path
from entry point to vulnerable use. Evidence locations link to the implicated
source lines; findings with no in-repo location anchor to the scanned manifest.

Re-runs update existing alerts rather than duplicating them. GitHub matches an
alert by rule id plus file location and refreshes the message, level, and
severity in place, so a verdict that flips from not-reachable to reachable
raises the level of the same alert. Findings that vanish from a later upload
close automatically. Keep `category` stable across runs, or alerts close and
get recreated.

A dismissed alert stays dismissed on later runs, including when the verdict
later flips to reachable. Reopen it from the alert page, or:

```sh
gh api -X PATCH repos/OWNER/REPO/code-scanning/alerts/N -f state=open
```

So avoid dismissing a not-reachable alert. It can hide a future reachable
verdict for the same package version.

## Cost control

Each finding is one agentic LLM session, typically 10 to 50 tool calls. Cost has
two dials: how many findings you analyze, and how much each one is allowed to
spend.

On a first run against a large project, start narrow on both:

```yaml
min-severity: high
max-findings: "5"          # how many findings get a session
max-cycles: "30"           # tool calls per finding
max-tokens: "150000"       # context tokens per finding
```

`max-cycles` and `max-tokens` are per-finding ceilings, and the first one
reached wins: further tool calls are denied and the model answers from the
evidence it already has. Reach for `max-tokens` with a large-context model, where
a cycle count says little about spend, and when tool results come back large.

Token usage per run is printed at the end of the log. Widen once you have a feel
for it.

## Troubleshooting

| Symptom | Cause and fix |
|---------|---------------|
| `Resource not accessible by integration` on upload-sarif | Missing `security-events: write` in the job's `permissions`. |
| Image pull fails | The version `action.yml` pins was never published, or the GHCR package is private. The tag it wants is the one in `runs.image` at the ref you pinned. |
| Copilot auth errors | Grant `copilot-requests: write` and enable the org's Copilot CLI billing policy, or pass a Copilot PAT as `github-token`, or switch to BYOK. |
| `reading -scan: no such file` | `scan-file` is not workspace-relative. Give the scanner an explicit `output-file` in the workspace. |
| `parsing -scan: unrecognized scan report format` | Not one of the five supported shapes. Pass `scan-format`, or check the scanner wrote JSON and not a table. |
| No alerts in the Security tab | Confirm the upload step ran (`if: always()`) and that code scanning is enabled on the repo. |
| Expected findings missing | Dropped by `only`, `min-severity`, `min-cvss`, `is-remote`, `is-exploited`, or the `max-findings` cap, or collapsed as a duplicate. Set `verbose: "true"` and the log names the stage that dropped them: `duplicate(s) collapsed`, `-only skipped N`, `severity/CVSS filters skipped N`, `exploitability filters dropped N`, `-max-findings cap dropped N`, then `analyzing N finding(s)`. |
| A finding errored | Its alert is emitted at warning level with "could not analyze" and the run continues. Per-finding logs are in the `xpsd-results` artifact. |
| Artifact upload fails with `EACCES` | Older images wrote root-only directories. Update to a current release. |

## Dry run before wiring CI

```sh
make docker
grype dir:/path/to/project -o json > /tmp/scan.json
./xpsd -source /path/to/project -scan /tmp/scan.json \
       -min-severity high -max-findings 3 \
       -sarif-out results.sarif
```

Check `out/xpsd/summary.md` and `results.sarif`. If those look right, the
action produces the same thing.
