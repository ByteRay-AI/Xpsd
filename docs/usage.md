# Using Xpsd

Xpsd runs in two modes. Single-CVE takes one vulnerability description; scan mode takes a
whole scanner report and produces one verdict per finding.

## Single CVE

```sh
./xpsd -source /path/to/project \
  -cve "CVE-2024-45337"

# or read the description from a file
./xpsd -source /path/to/project -cve-file cve.txt
```

Output lands in `out/xpsd/`:

- `verdict.json`: the structured verdict, straight from the analysis loop
- `report.md`: rendered report with a verdict table, summary, ASCII attack-flow
  graph, evidence, and details (only with `-no-markdown=false`)

## Scan mode

```sh
# 1. produce a scan (any of these)
grype sbom:sbom.cdx.json -o json > scan.json
trivy sbom sbom.cdx.json -f json -o scan.json
osv-scanner --sbom=sbom.cdx.json --format json > scan.json
snyk test --json > scan.json

# 2. analyze every finding
./xpsd -source /path/to/project -scan scan.json -sarif-out results.sarif
```

Supported formats, auto-detected, override with `-scan-format`:

| Producer | Format | Notes |
|----------|--------|-------|
| [Grype](https://github.com/anchore/grype) | `grype -o json` | also `-o sarif` |
| [Trivy](https://github.com/aquasecurity/trivy) | `trivy -f json` | also `-f sarif` |
| [OSV-Scanner](https://github.com/google/osv-scanner) | `--format json` | scans SBOMs natively |
| [Snyk](https://snyk.io) | `snyk test --json` | single project or `--all-projects` array |
| any SARIF producer | SARIF 2.1.0 | generic fallback |

Output under `out/xpsd/`:

- `verdicts.json`: every finding with its verdict
- `summary.md`: one line per finding
- `findings/<id>/`: per-finding `verdict.json`, `finding.json`, `report.md`
- `results.sarif` via `-sarif-out`: upload to GitHub code scanning

## Choosing what to analyze

Each finding is one agentic LLM session, so filtering is what controls cost.
The pipeline runs in this order:

1. **Dedup** by id, package, and version.
2. **Select by id** with `-only`. This runs first because an explicit id list
   needs no enriched data, so nothing is looked up that you already excluded.
3. **Enrich** from the OSV database, filling in the severity, CVSS score, and
   CVSS vector the scanner left out. These are plain HTTP lookups, not LLM
   calls.
4. **Filter** with `-min-severity`, `-min-cvss`, `-is-remote`, and
   `-is-exploited`, all deciding on the enriched data.
5. **Rank and cap**: sort by severity, then CVSS, and keep at most
   `-max-findings`.
6. **Analyze** reachability on what is left, one LLM session per finding.

Filtering before analysis is deliberate: every filter decides on complete data,
so no LLM session is ever spent on a finding a filter would have dropped. The
cap runs last, so `-max-findings 10` means ten findings analyzed, not ten
selected and then thinned by the gates.

```sh
-min-severity high              # drop everything below high
-min-cvss 7.0                   # numeric floor instead of the band
-max-findings 10                # top 10 by severity, then CVSS
-only CVE-2021-44228,GHSA-xxxx  # specific ids, aliases match too
-is-remote                      # only network-reachable (CVSS AV:N)
-is-exploited                   # only with known exploitation
```

All of these are ANDed, and the two exploitability gates need positive
evidence. `-is-remote` keeps a finding only when a CVSS vector shows `AV:N`, so
a finding with no vector is dropped: it cannot be shown to be remote.
`-is-exploited` keeps a finding only when the CVSS-BT dataset lists exploit
activity for it, so a CVE absent from the dataset is dropped too.

The severity and CVSS floors work the other way. An unscored finding passes
them, because a missing score is not a low score and enrichment has already had
its chance to supply one.

A feed that cannot be used at all is not the same as a CVE with no entry. If the
CVSS-BT download fails, `-is-exploited` stops the run with an error rather than
dropping every finding and reporting an empty result as though nothing
qualified.

`-no-enrich` skips the enrichment step, for example on an air-gapped runner. The filters then
judge on whatever the scan report already carried, which means an unscored
finding passes the severity and CVSS floors instead of being ranked properly.

### Remote and exploited

`-is-remote` keeps a finding when its CVSS vector says the attack vector is the
network (`AV:N`). Adjacent, local, and physical vectors are dropped. Both CVSS
v2 and v3 vectors are understood.

`-is-exploited` keeps a finding when the
[CVSS-BT](https://github.com/t0sche/cvss-bt) dataset shows real-world
exploitation or published exploit code: CISA KEV, VulnCheck KEV, ExploitDB,
Metasploit, Nuclei, or a proof of concept on GitHub.

The dataset is roughly 80 MB. It is fetched only when `-is-exploited` is set,
streamed rather than buffered, and the download stops early once every selected
CVE has been matched.

## Project context

Reachability often depends on facts that are not in the code: what actually
gets compiled, what ships, what is exposed to a network. `-guidance` passes
those in as ground truth.

```sh
./xpsd -source . -scan scan.json -guidance project-notes.txt
```

```
The ssh listener binds to localhost only and sits behind a firewall.
libfoo is vendored but never compiled into the shipped image.
The admin API is reachable only from the cluster's internal network.
```

The model is told to prefer this over generic assumptions when it settles a
question, and to still cite the code evidence it finds.

## Models and providers

By default Xpsd uses GitHub Copilot, so no API key is needed, but the
[GitHub Copilot CLI](https://github.com/github/copilot-cli) must be installed
and authenticated. Run `./xpsd -list-models` to see what the active provider
offers.

For a different provider, pass `-provider-type`, `-base-url`, and `-api-key`:

```sh
./xpsd -provider-type anthropic -api-key $ANTHROPIC_API_KEY ...
./xpsd -provider-type openai    -api-key $OPENAI_API_KEY ...
```

Keys are also read from `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or
`AZURE_OPENAI_KEY`.

## What the agent can do

The model has no shell and no filesystem access. Everything it can reach is one
of these tools, served by the bundled MCP server:

| Tool | Purpose |
|------|---------|
| `source_languages`, `source_dirs`, `expand_folder` | orient in the tree |
| `read_local_file`, `get_line_count`, `grep` | read and search source |
| `lang_search_pattern`, `lang_find_calls`, `lang_get_definition`, `lang_get_xrefs`, `lang_get_outline`, `lang_get_imports`, `lang_find_strings`, `lang_find_similar` | ast-grep structural search, call sites, definitions, cross-references |
| `osv_get_vuln` | fetch the OSV.dev advisory for a CVE/GHSA id |
| `fetch_url` | render a web page (advisory, commit, bug tracker) as markdown |
| `fetch_dependency_source` | clone or unpack a dependency that is not vendored in the tree, then analyze it with the tools above |

The source tools confine every path to the analyzed tree, which is mounted
read-only. `fetch_url` and `fetch_dependency_source` reach the network through a
validating proxy that refuses any non-public address; `-no-web` removes
`fetch_url` entirely.

One more tool, `run_python`, is disabled unless you set
`XPSD_ENABLE_RUN_PYTHON=1`. It executes arbitrary code and bypasses the proxy,
so read [SECURITY.md](../SECURITY.md) before enabling it.

## Verdict schema

```json
{
  "cve": "CVE-2024-45337",
  "reachable": "yes | no | uncertain",
  "confidence": "low | medium | high",
  "detected_version": "v0.3.4",
  "version_applicable": true,
  "vulnerable_code_present": true,
  "affected_component": "libfoo / parse_header",
  "evidence": [{ "file": "/src/...", "line": 42, "note": "..." }],
  "call_path": ["http handler", "...", "parse_header"],
  "rationale": "..."
}
```

`reachable` is a model judgment, not a proof. Read it with `confidence`, and
treat `uncertain` as "needs a human", not as "no".

### Per-finding budgets

`-max-cycles` caps tool calls and `-max-tokens` caps context tokens. Both are
ceilings on one finding's analysis, and whichever is reached first denies further
tool calls and asks the model to answer from the evidence it already has. Use
`-max-tokens` when a large-context model makes the cycle count a poor proxy for
spend.

## Adversarial review

Every decisive verdict is re-checked by a second, shorter session that tries to
break it. If the first pass said reachable, the reviewer looks for an edge in the
call path that is never taken or a gate that cannot open. If the first pass said
not reachable, the reviewer checks that the stated blocker really blocks and
looks for a path the first pass missed.

The reviewer gets source tools only: no web fetch, no advisory lookup, no
dependency download. A dependency the first pass already fetched stays readable
on disk, so the reviewer can still check a guard inside it. Its budget is
`-adversary-cycles` tool calls, 15 by default, against the primary loop's 50, and
`-adversary-tokens` context tokens. Both are separate from `-max-cycles` and
`-max-tokens`, so a short review never inherits the analysis allowance.

On disagreement the reviewer's answer wins, and its evidence and call path
replace the first pass's. The original rationale is kept in the verdict, so an
overturned conclusion stays visible in the report and the alert.

Two cases leave the verdict alone: an `uncertain` verdict, which is already
flagged for a human, and a disagreement with no file and line behind it. Set
`-adversary-cycles 0` to skip the pass entirely.

## Project layout, gathered once

Every analysis used to open by calling `source_languages` and `source_dirs`.
Those return the same bytes for every finding, so a scan of ten findings paid
for them ten times, at roughly a model turn each.

Xpsd now calls them once when the MCP server comes up and injects the result
into every prompt, including the adversarial review's. The agent is told the
layout is already gathered and not to re-fetch it. The information is identical;
only the round trip is gone. If the calls fail the block is omitted and the
prompt falls back to telling the agent to gather it itself.

## Cost reporting

A run ends with a usage line and the billed cost:

```
tokens: ~54488 sent, 19852 in context | LLM requests: 6 | tool calls: 5
  analysis: ~45293 tokens, 4 requests, 4 tool calls
  review:   ~9195 tokens, 2 requests, 1 tool calls
cost: $0.0841  (8411725000 nano-AIU reported by Copilot)
```

The cost is Copilot's own number, not a guess. Copilot bills in AI units, one
AIU being one cent, and reports the exact amount per API call; Xpsd sums those
across the run. In scan mode every figure on these lines is the total across all
findings, and the analysis and review stages are broken out so the second opinion
is priced separately.

"sent" is the input the run pushed through the model. An agent turn resends the
whole conversation, so it is the context size summed over the turns rather than
the size of the window at the end, which is what "in context" reports.

When the runtime reports no billing data the line says so:

```
cost: data not available, cannot estimate
```

That happens with a bring-your-own-key provider, which bills at your own account
on terms Xpsd cannot see, and on any endpoint that omits the field. Xpsd does not
fall back to a guess, because a wrong number is worse than a missing one.

## Logging

By default a run prints only the final verdict block, plus any warnings and
errors. `-v` adds the progress detail: the source tree the tools can see, MCP
startup, tool discovery, every tool call with its arguments, ReAct notices, and
the CLI's own debug log under `<out>/xpsd/copilot/`.

Every run also writes a full structured log to
`<out>/xpsd/logs/xpsd_<timestamp>.jsonl` regardless of `-v`, with one entry per
event including tool arguments and results.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | analysis completed |
| 1 | setup or analysis error |
| 2 | `-fail-on` threshold met |

`-fail-on reachable` fires on any `reachable=yes`. `-fail-on uncertain` also
fires on uncertain verdicts, unparseable output, and per-finding errors, which
is the stricter choice for gating a build.

## Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `-source` | (none) | project source directory (required) |
| `-cve` / `-cve-file` | (none) | vulnerability description (single-CVE mode) |
| `-scan` | (none) | scanner report; every finding is analyzed (scan mode) |
| `-scan-format` | `auto` | `grype` \| `trivy` \| `osv` \| `snyk` \| `sarif` |
| `-max-findings` | `0` | analyze at most N findings, highest severity first (0 = all) |
| `-min-severity` | (none) | skip findings below `low`/`medium`/`high`/`critical` |
| `-min-cvss` | `0` | skip findings with a CVSS base score below this (unscored kept) |
| `-is-remote` | off | only findings shown to be CVSS `AV:N`; no-vector findings dropped |
| `-is-exploited` | off | only findings listed as exploited in CVSS-BT; unlisted dropped |
| `-no-enrich` | off | disable OSV lookup of missing severity/CVSS/vector |
| `-only` | (none) | comma-separated CVE/GHSA ids to analyze (matches aliases too) |
| `-guidance` | (none) | file of authoritative project context injected into the prompt |
| `-fail-on` | (none) | exit 2 when verdicts reach `reachable` or `uncertain` |
| `-sarif-out` | (none) | write SARIF 2.1.0 for GitHub code scanning |
| `-out` | `out` | parent output directory; artifacts go under `<out>/xpsd/` |
| `-max-cycles` | `50` | tool-call budget per analysis loop |
| `-max-tokens` | `0` | deny tool calls past N context tokens (0 = off) |
| `-adversary-cycles` | `15` | tool-call budget for the adversarial review pass (0 = off) |
| `-adversary-tokens` | `0` | context-token budget for that pass (0 = unlimited) |
| `-max-result-kb` | `32` | truncate any single tool result over this size |
| `-max-tool-output-kb` | `24` | MCP inline response cap in KB; larger results spill to a file the tools can read |
| `-tool-timeout` | `300000` | per-tool-call MCP timeout (ms) |
| `-timeout` | `1h` | wall-clock timeout per analysis loop |
| `-no-web` | off | disable the `fetch_url` tool |
| `-no-markdown` | on | skip markdown report rendering; `-no-markdown=false` to render it |
| `-model` / `-effort` | provider default | model selection |
| `-provider-type` / `-base-url` / `-api-key` | (none) | BYOK (openai/anthropic/azure); omit for Copilot |
| `-mcp-bin` | `/usr/local/bin/mcp` | path to the MCP server binary |
| `-list-models` | (none) | list available models and exit |
| `-version` | (none) | print the build version and exit |
| `-v` | off | progress logs: MCP startup, tool discovery, each tool call with arguments, ReAct notices |
