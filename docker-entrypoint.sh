#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 ByteRay Ltd.
set -e

# GitHub keeps hyphens in INPUT_ names (out-dir -> INPUT_OUT-DIR), which bash
# cannot expand; read inputs via printenv.
input() {
    printenv "INPUT_$1" 2>/dev/null || printenv "INPUT_${1//-/_}" 2>/dev/null || true
}

if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
    # Checkout root inside the action container.
    ws="${GITHUB_WORKSPACE:-/github/workspace}"
    source_rel="$(input SOURCE)"
    out_rel="$(input OUT-DIR)"
    src="${ws}/${source_rel:-.}"
    out="${ws}/${out_rel:-xpsd-results}"
    sarif="${out}/xpsd/results.sarif"

    args=(
        -mcp-bin /usr/local/bin/mcp
        -source  "$src"
        -out     "$out"
        -sarif-out "$sarif"
    )

    cve="$(input CVE)";                   [ -n "$cve" ]      && args+=(-cve "$cve")
    cve_file="$(input CVE-FILE)";         [ -n "$cve_file" ] && args+=(-cve-file "${ws}/${cve_file}")
    scan_file="$(input SCAN-FILE)";       [ -n "$scan_file" ] && args+=(-scan "${ws}/${scan_file}")
    scan_format="$(input SCAN-FORMAT)";   [ -n "$scan_format" ] && args+=(-scan-format "$scan_format")
    max_findings="$(input MAX-FINDINGS)"; [ -n "$max_findings" ] && [ "$max_findings" != "0" ] && args+=(-max-findings "$max_findings")
    min_severity="$(input MIN-SEVERITY)"; [ -n "$min_severity" ] && args+=(-min-severity "$min_severity")
    min_cvss="$(input MIN-CVSS)";         [ -n "$min_cvss" ] && args+=(-min-cvss "$min_cvss")
    [ "$(input NO-ENRICH)" = "true" ] && args+=(-no-enrich)
    [ "$(input IS-REMOTE)" = "true" ] && args+=(-is-remote)
    [ "$(input IS-EXPLOITED)" = "true" ] && args+=(-is-exploited)
    only="$(input ONLY)";                 [ -n "$only" ] && args+=(-only "$only")
    fail_on="$(input FAIL-ON)";           [ -n "$fail_on" ] && args+=(-fail-on "$fail_on")
    # guidance arrives as inline text; guidance-file names a file in the repo.
    guidance="$(input GUIDANCE)"
    guidance_file="$(input GUIDANCE-FILE)"
    if [ -n "$guidance" ]; then
        printf '%s\n' "$guidance" > /tmp/xpsd-guidance.txt
        args+=(-guidance /tmp/xpsd-guidance.txt)
    elif [ -n "$guidance_file" ]; then
        args+=(-guidance "${ws}/${guidance_file}")
    fi
    model="$(input MODEL)";               [ -n "$model" ]    && args+=(-model "$model")
    effort="$(input EFFORT)";             [ -n "$effort" ]   && args+=(-effort "$effort")
    max_cycles="$(input MAX-CYCLES)";     [ -n "$max_cycles" ] && args+=(-max-cycles "$max_cycles")
    max_tokens="$(input MAX-TOKENS)";     [ -n "$max_tokens" ] && [ "$max_tokens" != "0" ] && args+=(-max-tokens "$max_tokens")
    adv_cycles="$(input ADVERSARY-CYCLES)"; [ -n "$adv_cycles" ] && args+=(-adversary-cycles "$adv_cycles")
    adv_tokens="$(input ADVERSARY-TOKENS)"; [ -n "$adv_tokens" ] && [ "$adv_tokens" != "0" ] && args+=(-adversary-tokens "$adv_tokens")
    provider="$(input PROVIDER-TYPE)";    [ -n "$provider" ] && args+=(-provider-type "$provider")
    base_url="$(input BASE-URL)";         [ -n "$base_url" ] && args+=(-base-url "$base_url")
    api_key="$(input API-KEY)";           [ -n "$api_key" ]  && args+=(-api-key "$api_key")
    [ "$(input NO-WEB)"      = "true" ] && args+=(-no-web)
    [ "$(input NO-MARKDOWN)" = "false" ] && args+=(-no-markdown=false)
    [ "$(input VERBOSE)"     = "true" ] && args+=(-v)

    # Capture exit code; write outputs even when -fail-on exits 2.
    rc=0
    xpsd "${args[@]}" || rc=$?

    if [ -n "${GITHUB_OUTPUT:-}" ]; then
        sarif_rel="${out_rel:-xpsd-results}/xpsd/results.sarif"
        reachable=""
        reachable_count=""
        if [ -n "$scan_file" ]; then
            # Scan mode: aggregate over verdicts.json.
            counts=$(python3 - "$out/xpsd/verdicts.json" <<'PY' 2>/dev/null || true
import json, sys
entries = json.load(open(sys.argv[1]))
n = sum(1 for e in entries if (e.get("verdict") or {}).get("reachable") == "yes")
print(f"{n} {'yes' if n else 'no'}")
PY
)
            reachable_count="${counts%% *}"
            reachable="${counts##* }"
        else
            reachable=$(python3 -c \
                "import json,sys; d=json.load(open(sys.argv[1])); print(d.get('reachable',''))" \
                "$out/xpsd/verdict.json" 2>/dev/null || true)
        fi
        {
            printf 'sarif-file=%s\n'      "$sarif_rel"
            printf 'reachable=%s\n'       "$reachable"
            printf 'reachable-count=%s\n' "$reachable_count"
        } >> "$GITHUB_OUTPUT"
    fi
    exit "$rc"
fi

# Ad-hoc / shell-script mode: pass all args straight through.
exec xpsd -mcp-bin /usr/local/bin/mcp "$@"
