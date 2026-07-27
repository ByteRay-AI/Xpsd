// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ByteRay Ltd.

// Command xpsd runs LLM-driven reachability analysis: given a vulnerability
// (a CVE description, or a whole scanner report) and a project source tree, it
// decides whether each vulnerability is reachable in that codebase.
//
// The command spawns the trimmed MCP server (common file tools + ast-grep) as
// a child process pointed at the source, runs the analysis loop(s), then shuts
// the server down and writes JSON verdicts, a markdown report, and optionally
// SARIF for GitHub code scanning.
package main

import (
	"context"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	copilot "github.com/github/copilot-sdk/go"
)

type singleModeConfig struct {
	RunDir     string
	SrcAbs     string
	URIPrefix  string
	SarifOut   string
	NoMarkdown bool
	FailOn     string
	Guidance   string
}

type scanModeConfig struct {
	RunDir     string
	SrcAbs     string
	URIPrefix  string
	SarifOut   string
	NoMarkdown bool
	FailOn     string
	Guidance   string
}

func main() {
	os.Exit(run())
}

// run holds the real main body.
func run() int {
	var (
		source      = flag.String("source", "", "path to the project source directory to analyze (required)")
		cveText     = flag.String("cve", "", "CVE / vulnerability description text (or use -cve-file / -scan)")
		cveFile     = flag.String("cve-file", "", "path to a file containing the CVE / vulnerability description")
		scanFile    = flag.String("scan", "", "path to a vulnerability scan report (Grype, Trivy, OSV-Scanner, Snyk JSON, or SARIF); every finding is analyzed")
		scanFormat  = flag.String("scan-format", FormatAuto, "scan report format: auto|grype|trivy|osv|snyk|sarif")
		maxFind     = flag.Int("max-findings", 0, "analyze at most N findings from -scan, highest severity first (0 = all)")
		minSev      = flag.String("min-severity", "", "skip -scan findings below this severity: low|medium|high|critical")
		minCVSS     = flag.Float64("min-cvss", 0, "skip -scan findings whose CVSS base score is below this value (0 = off; findings with no score are kept)")
		onlyIDs     = flag.String("only", "", "comma-separated vulnerability ids (CVE/GHSA/...) to analyze from -scan; matches ids and aliases")
		isRemote    = flag.Bool("is-remote", false, "only analyze findings that are remotely exploitable (CVSS AV:N)")
		isExploited = flag.Bool("is-exploited", false, "only analyze findings with known exploitation or public exploit code (CVSS-BT: CISA/VulnCheck KEV, ExploitDB, Metasploit, Nuclei)")
		noEnrich    = flag.Bool("no-enrich", false, "do not look up missing severity / CVSS scores from the OSV database before filtering")
		failOn      = flag.String("fail-on", "", "exit with code 2 when verdicts reach this threshold: reachable (any reachable=yes) | uncertain (also uncertain/unparsed/errored)")
		guidance    = flag.String("guidance", "", "path to a file with authoritative operator guidance about this project (build, deployment, exposure); injected into the analysis prompt")
		outDir      = flag.String("out", "out", "parent output directory; artifacts go under <out>/xpsd/")
		mcpBin      = flag.String("mcp-bin", "/usr/local/bin/mcp", "path to the mcp binary")
		model       = flag.String("model", "", "model name (default: provider-dependent)")
		effort      = flag.String("effort", "", "reasoning effort: low, medium, high, xhigh")
		provider    = flag.String("provider-type", "", "BYOK provider type: openai, anthropic, azure (omit for GitHub Copilot)")
		baseURL     = flag.String("base-url", "", "BYOK base URL")
		apiKey      = flag.String("api-key", "", "BYOK API key (or env OPENAI_API_KEY / ANTHROPIC_API_KEY)")
		maxCycles   = flag.Int("max-cycles", 50, "tool-call budget for each analysis loop")
		maxTokens   = flag.Int("max-tokens", 0, "deny further tool calls past this many context tokens (0 = unlimited)")
		maxResult   = flag.Int("max-result-kb", 32, "truncate any single MCP tool result larger than this many KB")
		mcpOutKB    = flag.Int("max-tool-output-kb", 24, "mcp: max inline tool-result size in KB before spilling to a tmp file")
		toolTOms    = flag.Int("tool-timeout", 300000, "per-tool-call MCP timeout in milliseconds")
		timeout     = flag.Duration("timeout", time.Hour, "wall-clock timeout per analysis loop")
		noWeb       = flag.Bool("no-web", false, "disable the fetch_url tool (skips starting the web-fetcher)")
		noMarkdown  = flag.Bool("no-markdown", true, "skip the markdown report rendering pass (default); pass -no-markdown=false to also render per-finding reports")
		sarifOut    = flag.String("sarif-out", "", "write a SARIF 2.1.0 file to this path (optional)")
		listModels  = flag.Bool("list-models", false, "list available models and exit")
		showVer     = flag.Bool("version", false, "print version and exit")
		verbose     = flag.Bool("v", false, "verbose logging")
	)
	flag.Parse()
	SetVerbose(*verbose)

	if *showVer {
		fmt.Println(buildVersion)
		return 0
	}

	// Cancel on SIGINT/SIGTERM (Ctrl-C, GitHub Actions job cancellation).
	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	// List models and exit.
	if *listModels {
		models, err := ListModels(ctx, ListModelsOpts{
			ProviderType: *provider, BaseURL: *baseURL, APIKey: *apiKey, Verbose: *verbose,
		})
		if err != nil {
			log.Fatalf("listing models: %v", err)
		}
		PrintModels(models)
		return 0
	}

	switch *failOn {
	case "", "reachable", "uncertain":
	default:
		log.Fatalf("invalid -fail-on %q (want reachable|uncertain)", *failOn)
	}

	// Resolve the input: exactly one of -cve / -cve-file / -scan.
	cve := strings.TrimSpace(*cveText)
	if *cveFile != "" {
		data, err := os.ReadFile(*cveFile)
		if err != nil {
			log.Fatalf("reading -cve-file: %v", err)
		}
		cve = strings.TrimSpace(string(data))
	}
	modes := 0
	for _, set := range []bool{*cveText != "", *cveFile != "", *scanFile != ""} {
		if set {
			modes++
		}
	}
	if modes != 1 || *source == "" {
		fmt.Fprintln(os.Stderr, "error: -source and exactly one of -cve / -cve-file / -scan are required")
		flag.Usage()
		return 1
	}
	if cve == "" && *scanFile == "" {
		log.Fatalf("empty vulnerability description")
	}

	// The filter pipeline only runs in scan mode; say so rather than ignoring them.
	if *scanFile == "" {
		var ignored []string
		for name, set := range map[string]bool{
			"-min-severity": *minSev != "", "-min-cvss": *minCVSS > 0,
			"-max-findings": *maxFind > 0, "-only": *onlyIDs != "",
			"-is-remote": *isRemote, "-is-exploited": *isExploited,
			"-no-enrich": *noEnrich,
		} {
			if set {
				ignored = append(ignored, name)
			}
		}
		if len(ignored) > 0 {
			sort.Strings(ignored)
			log.Printf("warning: %s only apply with -scan and are ignored here",
				strings.Join(ignored, ", "))
		}
	}

	var guidanceText string
	if *guidance != "" {
		data, err := os.ReadFile(*guidance)
		if err != nil {
			log.Fatalf("reading -guidance: %v", err)
		}
		guidanceText = strings.TrimSpace(string(data))
		if guidanceText != "" {
			vlog("operator guidance: %d bytes from %s", len(guidanceText), *guidance)
		}
	}

	// Parse the scan report up front.
	var findings []Finding
	if *scanFile != "" {
		data, err := os.ReadFile(*scanFile)
		if err != nil {
			log.Fatalf("reading -scan: %v", err)
		}
		parsed, format, err := ParseScan(data, *scanFormat)
		if err != nil {
			log.Fatalf("parsing -scan: %v", err)
		}
		var only []string
		if *onlyIDs != "" {
			only = strings.Split(*onlyIDs, ",")
		}

		// Dedup, then enrich, then filter, so every filter decides on complete
		// data and no LLM session is spent on a finding a filter would drop.
		// The cap is applied last, so -max-findings counts analyzed findings.
		deduped, dupes := DedupFindings(parsed)
		vlog("scan report: format=%s, %d finding(s), %d duplicate(s) collapsed",
			format, len(deduped), dupes)

		// -only needs no enriched data, so narrow first and keep the OSV
		// lookups to the ids actually under analysis.
		deduped, byID := SelectByIDs(deduped, only)
		if byID > 0 {
			vlog("-only skipped %d finding(s)", byID)
		}

		if !*noEnrich {
			if n := EnrichFindings(ctx, deduped, *isRemote); n > 0 {
				vlog("enriched %d finding(s) with severity/CVSS from OSV", n)
			}
		}

		selected, skipped, err := SelectFindings(deduped, *minSev, *minCVSS, nil)
		if err != nil {
			log.Fatalf("%v", err)
		}
		if skipped > 0 {
			vlog("severity/CVSS filters skipped %d finding(s)", skipped)
		}

		if *isRemote || *isExploited {
			var dropped int
			selected, dropped, err = FilterExploitability(ctx, selected, *isRemote, *isExploited)
			if err != nil {
				log.Fatalf("%v", err)
			}
			if dropped > 0 {
				vlog("exploitability filters dropped %d finding(s)", dropped)
			}
		}

		var capped int
		findings, capped = RankAndCap(selected, *maxFind)
		if capped > 0 {
			vlog("-max-findings cap dropped %d finding(s)", capped)
		}
		vlog("analyzing %d finding(s)", len(findings))

		if len(findings) == 0 {
			vlog("nothing to analyze")
		}
	}

	srcAbs, err := filepath.Abs(*source)
	if err != nil {
		log.Fatalf("resolving -source: %v", err)
	}
	if info, err := os.Stat(srcAbs); err != nil || !info.IsDir() {
		log.Fatalf("invalid -source %q: must be an existing directory (err=%v)", *source, err)
	}

	runDir := filepath.Join(*outDir, "xpsd")
	logDir := filepath.Join(runDir, "logs")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		log.Fatalf("creating output dir: %v", err)
	}
	// The container runs as root; CI collects the artifacts as another user.
	defer makeWorldReadable(*outDir)

	// Start the web-fetcher service; the MCP server's fetch_url tool proxies to it.
	var webURL string
	if !*noWeb {
		var stopWeb func()
		webURL, stopWeb = startWebFetcher(ctx)
		defer stopWeb()
	}

	mcpPath := *mcpBin
	if _, err := os.Stat(mcpPath); err != nil {
		log.Printf("mcp binary not found at %s: %v", mcpPath, err)
		return 1
	}
	port, err := freePort()
	if err != nil {
		log.Printf("finding free port: %v", err)
		return 1
	}
	mcpAddr := fmt.Sprintf("127.0.0.1:%d", port)
	mcpURL := fmt.Sprintf("http://%s/mcp", mcpAddr)

	mcpArgs := []string{"-source", srcAbs, "-addr", mcpAddr, "-out", runDir, "-max-tool-output-kb", fmt.Sprint(*mcpOutKB)}
	if webURL != "" {
		mcpArgs = append(mcpArgs, "-web-fetcher-url", webURL)
	}
	if *verbose {
		mcpArgs = append(mcpArgs, "-v")
	}
	mcp := exec.Command(mcpPath, mcpArgs...)
	mcp.Stdout = os.Stderr
	mcp.Stderr = os.Stderr
	if err := mcp.Start(); err != nil {
		log.Printf("starting MCP server (%s): %v", mcpPath, err)
		return 1
	}
	defer func() {
		if mcp.Process != nil {
			_ = mcp.Process.Kill()
			_, _ = mcp.Process.Wait()
		}
	}()
	vlog("started MCP server pid=%d at %s (source=%s)", mcp.Process.Pid, mcpURL, srcAbs)

	if err := waitForMCP(mcpURL, 30*time.Second); err != nil {
		log.Printf("MCP server did not become ready: %v", err)
		return 1
	}
	vlog("MCP server ready at %s", mcpURL)

	logger, err := NewNamedSessionLogger(logDir, "xpsd")
	if err != nil {
		log.Printf("creating session logger: %v", err)
		return 1
	}
	defer logger.Close()

	// -v puts the CLI at debug level with its state under the run dir.
	clientOpts := &copilot.ClientOptions{LogLevel: LogLevel(*verbose)}
	if *verbose {
		clientOpts.BaseDirectory = filepath.Join(runDir, "copilot")
	}
	client := copilot.NewClient(clientOpts)
	if err := client.Start(ctx); err != nil {
		log.Printf("starting copilot client: %v", err)
		return 1
	}
	defer client.Stop()

	opts := SessionOpts{
		MCPURL:          mcpURL,
		TargetPath:      srcAbs,
		Model:           *model,
		ReasoningEffort: *effort,
		ProviderType:    *provider,
		BaseURL:         *baseURL,
		APIKey:          *apiKey,
		Timeout:         *timeout,
		MaxCycles:       *maxCycles,
		MaxResultKB:     *maxResult,
		MaxTokens:       *maxTokens,
		ToolTimeout:     *toolTOms,
		Verbose:         *verbose,
		Logger:          logger,
	}

	modelName := *model
	if modelName == "" {
		modelName = "(provider default)"
	}
	effortName := *effort
	if effortName == "" {
		effortName = "(provider default)"
	}
	vlog("analysis: model=%s effort=%s", modelName, effortName)

	if *scanFile != "" {
		return runScanMode(ctx, client, opts, findings, scanModeConfig{
			RunDir:     runDir,
			SrcAbs:     srcAbs,
			URIPrefix:  sarifURIPrefix(srcAbs),
			SarifOut:   *sarifOut,
			NoMarkdown: *noMarkdown,
			FailOn:     *failOn,
			Guidance:   guidanceText,
		})
	}
	return runSingleMode(ctx, client, opts, cve, singleModeConfig{
		RunDir:     runDir,
		SrcAbs:     srcAbs,
		URIPrefix:  sarifURIPrefix(srcAbs),
		SarifOut:   *sarifOut,
		NoMarkdown: *noMarkdown,
		FailOn:     *failOn,
		Guidance:   guidanceText,
	})
}

// sarifURIPrefix returns the checkout-root-relative path of the analyzed
// source dir when running inside GitHub Actions with -source pointing at a
// subdirectory. Empty outside Actions or when the source is the checkout root
// itself.
func sarifURIPrefix(srcAbs string) string {
	ws := os.Getenv("GITHUB_WORKSPACE")
	if ws == "" {
		return ""
	}
	wsAbs, err := filepath.Abs(ws)
	if err != nil {
		return ""
	}
	rel, err := filepath.Rel(wsAbs, srcAbs)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return ""
	}
	return filepath.ToSlash(rel)
}

// runSingleMode analyzes one CVE description.
func runSingleMode(ctx context.Context, client *copilot.Client, opts SessionOpts, cve string, cfg singleModeConfig) int {
	var usage SessionUsage
	opts.UsageOut = &usage

	vlog("running reachability analysis (max-cycles=%d)…", opts.MaxCycles)
	output, err := RunSession(ctx, client, opts, reachabilitySystemPrompt, buildUserMessage(cve, cfg.Guidance))
	if err != nil {
		log.Printf("analysis failed: %v", err)
		return 1
	}

	// Extract the verdict JSON tolerantly; models occasionally wrap it in fences or prose.
	verdictText := extractVerdictJSON(output)
	verdictPath := filepath.Join(cfg.RunDir, "verdict.json")
	if err := os.WriteFile(verdictPath, []byte(verdictText+"\n"), 0o644); err != nil {
		log.Printf("warning: writing verdict.json: %v", err)
	}
	parsed := parseVerdict(verdictText)
	if parsed == nil {
		log.Printf("warning: verdict output did not parse as JSON; SARIF and action outputs may be incomplete")
	}

	if cfg.SarifOut != "" {
		writeSARIFFile(cfg.SarifOut, func() ([]byte, error) {
			return VerdictToSARIF(verdictText, cfg.SrcAbs, cfg.URIPrefix)
		})
	}

	// Second pass: render the verdict into a markdown report (skipped with -no-markdown).
	reportPath := filepath.Join(cfg.RunDir, "report.md")
	var rerr error
	if !cfg.NoMarkdown {
		vlog("rendering markdown report…")
		var report string
		report, rerr = RunText(ctx, client, opts, renderSystemPrompt, buildRenderUserMessage(cve, verdictText))
		if rerr != nil {
			log.Printf("warning: markdown rendering failed: %v", rerr)
		} else if err := os.WriteFile(reportPath, []byte(strings.TrimSpace(report)+"\n"), 0o644); err != nil {
			log.Printf("warning: writing report.md: %v", err)
			rerr = err
		}
	}

	fmt.Println()
	fmt.Println(strings.Repeat("─", 60))
	fmt.Println(verdictText)
	fmt.Println(strings.Repeat("─", 60))
	fmt.Printf("tokens used: %.0f | LLM requests: %d\n", usage.Tokens, usage.Requests)
	fmt.Printf("verdict: %s\n", verdictPath)
	if !cfg.NoMarkdown && rerr == nil {
		fmt.Printf("report:  %s\n", reportPath)
	}

	counts := CountResults([]FindingResult{{Verdict: parsed, Raw: verdictText}})
	if FailOnTriggered(cfg.FailOn, counts) {
		log.Printf("-fail-on=%s triggered", cfg.FailOn)
		return 2
	}
	return 0
}

// runScanMode analyzes every finding from a scan report sequentially and
// writes the aggregated artifacts.
func runScanMode(ctx context.Context, client *copilot.Client, opts SessionOpts, findings []Finding, cfg scanModeConfig) int {
	var totalUsage SessionUsage

	deps := ScanDeps{
		RunDir: cfg.RunDir,
		Analyze: func(ctx context.Context, f Finding, description string) (string, error) {
			runOpts := opts
			var usage SessionUsage
			runOpts.UsageOut = &usage
			out, err := RunSession(ctx, client, runOpts, reachabilitySystemPrompt, buildUserMessage(description, cfg.Guidance))
			totalUsage.Tokens += usage.Tokens
			totalUsage.Requests += usage.Requests
			return out, err
		},
	}
	if !cfg.NoMarkdown {
		deps.Render = func(ctx context.Context, description, verdictJSON string) (string, error) {
			return RunText(ctx, client, opts, renderSystemPrompt, buildRenderUserMessage(description, verdictJSON))
		}
	}

	results := RunScan(ctx, deps, findings)

	verdictsPath, err := WriteScanArtifacts(cfg.RunDir, results)
	if err != nil {
		log.Printf("warning: %v", err)
	}

	if cfg.SarifOut != "" {
		writeSARIFFile(cfg.SarifOut, func() ([]byte, error) {
			return BuildScanSARIF(results, cfg.SrcAbs, cfg.URIPrefix)
		})
	}

	counts := CountResults(results)
	fmt.Println()
	fmt.Println(strings.Repeat("─", 60))
	fmt.Printf("findings analyzed: %d | reachable: %d | not reachable: %d | uncertain: %d | unparsed: %d | errors: %d\n",
		len(results), counts.Reachable, counts.NotReachable, counts.Uncertain, counts.Unparsed, counts.Errors)
	fmt.Println(strings.Repeat("─", 60))
	fmt.Printf("tokens used: %.0f | LLM requests: %d\n", totalUsage.Tokens, totalUsage.Requests)
	if verdictsPath != "" {
		fmt.Printf("verdicts: %s\n", verdictsPath)
		fmt.Printf("summary:  %s\n", filepath.Join(cfg.RunDir, "summary.md"))
	}

	if FailOnTriggered(cfg.FailOn, counts) {
		log.Printf("-fail-on=%s triggered", cfg.FailOn)
		return 2
	}
	return 0
}

// writeSARIFFile generates and writes a SARIF file, logging (not failing) on error.
func writeSARIFFile(path string, build func() ([]byte, error)) {
	data, err := build()
	if err != nil {
		log.Printf("warning: generating SARIF: %v", err)
		return
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			log.Printf("warning: creating SARIF dir: %v", err)
			return
		}
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		log.Printf("warning: writing SARIF: %v", err)
		return
	}
	vlog("SARIF written to %s", path)
}

// makeWorldReadable widens permissions on everything under root.
func makeWorldReadable(root string) {
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			os.Chmod(p, 0o755)
		} else {
			os.Chmod(p, 0o644)
		}
		return nil
	})
}

// freePort asks the OS for an unused TCP port and returns it.
func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

// waitForMCP polls the MCP server until it responds to an initialize request
// or the deadline elapses.
func waitForMCP(url string, within time.Duration) error {
	deadline := time.Now().Add(within)
	var last error
	for time.Now().Before(deadline) {
		if err := CheckMCP(url); err == nil {
			return nil
		} else {
			last = err
		}
		time.Sleep(300 * time.Millisecond)
	}
	return last
}
