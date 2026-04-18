/*
Copyright AppsCode Inc. and Contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package remediate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-github/v84/github"
	"golang.org/x/mod/semver"
	"golang.org/x/oauth2"
)

const (
	stdlibModule    = "stdlib"
	toolchainModule = "toolchain"
	maxPerPage      = 100

	defaultSecondaryRetryDelay = time.Minute
	defaultServerErrorDelay    = 5 * time.Second
	maxSecondaryRetryDelay     = 15 * time.Minute
	maxRateLimitRetryAttempts  = 8
)

var (
	errNoRepoInfo  = errors.New("github repository was not provided and could not be inferred")
	errNoGitHubPAT = errors.New("github token is required for Dependabot alerts")

	sshRepoPattern   = regexp.MustCompile(`^(?:ssh://)?git@github\.com[:/]([^/]+)/([^/]+?)(?:\.git)?$`)
	httpsRepoPattern = regexp.MustCompile(`^https://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$`)
)

type Config struct {
	ProjectDir    string
	Repo          string
	GitHubToken   string
	Patterns      []string
	MaxIterations int
	EnableGo      bool
	EnableNPM     bool
	DryRun        bool
	Stdout        io.Writer
	Stderr        io.Writer
}

type govulncheckMessage struct {
	Finding *govulncheckFinding `json:"finding,omitempty"`
}

type govulncheckFinding struct {
	OSV          string             `json:"osv,omitempty"`
	FixedVersion string             `json:"fixed_version,omitempty"`
	Trace        []govulncheckFrame `json:"trace,omitempty"`
}

type govulncheckFrame struct {
	Module   string `json:"module,omitempty"`
	Package  string `json:"package,omitempty"`
	Function string `json:"function,omitempty"`
}

type govScan struct {
	UniqueOSVs map[string]struct{}
	Findings   []*govulncheckFinding
}

type upgradeTarget struct {
	Module  string
	Version string
	Kind    targetKind
	Sources map[string]struct{}
	OSVs    map[string]struct{}
	Alerts  map[string]struct{}
}

type targetKind string

const (
	targetModule    targetKind = "module"
	targetToolchain targetKind = "toolchain"
)

func ptr[T any](value T) *T {
	return &value
}

func Run(ctx context.Context, cfg Config) error {
	stdout := cfg.Stdout
	stderr := cfg.Stderr
	if stdout == nil {
		stdout = os.Stdout
	}
	if stderr == nil {
		stderr = os.Stderr
	}

	goEnabled := cfg.EnableGo
	npmEnabled := cfg.EnableNPM
	if !goEnabled && !npmEnabled {
		return errors.New("at least one ecosystem must be enabled via --go or --npm")
	}

	projectDirValue := strings.TrimSpace(cfg.ProjectDir)
	if projectDirValue == "" {
		projectDirValue = "."
	}

	projectDir, err := filepath.Abs(projectDirValue)
	if err != nil {
		return fmt.Errorf("resolve project directory: %w", err)
	}

	patterns := cfg.Patterns
	if len(patterns) == 0 {
		patterns = []string{"./..."}
	}
	if cfg.MaxIterations <= 0 {
		cfg.MaxIterations = 10
	}

	goDirs, npmDirs, err := discoverManifestDirs(projectDir)
	if err != nil {
		return err
	}

	if goEnabled && len(goDirs) == 0 {
		fmt.Fprintln(stdout, "No go.mod files found; skipping Go remediation.")
	}
	if npmEnabled && len(npmDirs) == 0 {
		fmt.Fprintln(stdout, "No package.json files found; skipping npm remediation.")
	}

	if (!goEnabled || len(goDirs) == 0) && (!npmEnabled || len(npmDirs) == 0) {
		return fmt.Errorf("no supported manifests found under %s", projectDir)
	}

	var owner string
	var name string
	var client *github.Client
	if goEnabled && len(goDirs) > 0 {
		owner, name, client, err = resolveGitHubClient(ctx, cfg, projectDir)
		if err != nil {
			return err
		}

		for _, dir := range goDirs {
			fmt.Fprintf(stdout, "Go remediation in %s\n", dir)
			if err := runGoRemediation(ctx, cfg, dir, patterns, owner, name, client, stdout, stderr); err != nil {
				return err
			}
		}
	}

	if npmEnabled {
		for _, dir := range npmDirs {
			if err := runNPMAuditFix(ctx, dir, cfg.DryRun, stdout, stderr); err != nil {
				return err
			}
		}
	}

	return nil
}

func resolveGitHubClient(ctx context.Context, cfg Config, projectDir string) (string, string, *github.Client, error) {
	repo := strings.TrimSpace(cfg.Repo)
	if repo == "" {
		repo = strings.TrimSpace(os.Getenv("GITHUB_REPOSITORY"))
	}
	if repo == "" {
		var err error
		repo, err = detectRepoFromGit(ctx, projectDir)
		if err != nil && !errors.Is(err, errNoRepoInfo) {
			return "", "", nil, err
		}
	}
	if repo == "" {
		return "", "", nil, errNoRepoInfo
	}

	owner, name, err := splitRepo(repo)
	if err != nil {
		return "", "", nil, err
	}

	token := strings.TrimSpace(cfg.GitHubToken)
	for _, envVar := range []string{"GITHUB_TOKEN", "GH_TOOLS_TOKEN"} {
		if token != "" {
			break
		}
		token = strings.TrimSpace(os.Getenv(envVar))
	}
	if token == "" {
		return "", "", nil, errNoGitHubPAT
	}

	client := newGitHubClient(ctx, token)
	return owner, name, client, nil
}

func newGitHubClient(ctx context.Context, token string) *github.Client {
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	httpClient := oauth2.NewClient(ctx, ts)

	baseTransport := httpClient.Transport
	if baseTransport == nil {
		baseTransport = http.DefaultTransport
	}
	httpClient.Transport = &rateLimitTransport{base: baseTransport}

	return github.NewClient(httpClient)
}

type rateLimitTransport struct {
	base http.RoundTripper
}

func (t *rateLimitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	canRetryBody := req.Body == nil || req.Body == http.NoBody || req.GetBody != nil

	for attempt := 0; ; attempt++ {
		currReq := req
		if attempt > 0 {
			currReq = req.Clone(req.Context())
			if req.GetBody != nil {
				body, err := req.GetBody()
				if err != nil {
					return nil, err
				}
				currReq.Body = body
			}
		}

		resp, err := t.base.RoundTrip(currReq)
		if err != nil {
			return nil, err
		}
		if resp == nil {
			return nil, nil
		}

		retryable := resp.StatusCode == http.StatusForbidden ||
			resp.StatusCode == http.StatusTooManyRequests ||
			resp.StatusCode == http.StatusInternalServerError
		if !retryable {
			return resp, nil
		}
		if attempt >= maxRateLimitRetryAttempts || !canRetryBody {
			return resp, nil
		}

		delay := retryDelay(resp, attempt)
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		timer := time.NewTimer(delay)
		select {
		case <-req.Context().Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil, req.Context().Err()
		case <-timer.C:
		}
	}
}

func retryDelay(resp *http.Response, attempt int) time.Duration {
	if resp.StatusCode == http.StatusInternalServerError {
		backoff := minDuration(
			time.Duration(float64(defaultServerErrorDelay)*math.Pow(2, float64(attempt))),
			maxSecondaryRetryDelay,
		)
		return maxDuration(backoff, time.Second)
	}

	return rateLimitRetryDelay(resp, attempt)
}

func rateLimitRetryDelay(resp *http.Response, secondaryAttempt int) time.Duration {
	retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
	if retryAfter > 0 {
		return retryAfter
	}

	if resp.Header.Get("X-RateLimit-Remaining") == "0" {
		if reset := parseUnixTime(resp.Header.Get("X-RateLimit-Reset")); !reset.IsZero() {
			return maxDuration(time.Until(reset)+time.Second, time.Second)
		}
	}

	backoff := minDuration(
		time.Duration(float64(defaultSecondaryRetryDelay)*math.Pow(2, float64(secondaryAttempt))),
		maxSecondaryRetryDelay,
	)
	return maxDuration(backoff, time.Second)
}

func parseRetryAfter(value string) time.Duration {
	if value == "" {
		return 0
	}

	seconds, err := strconv.Atoi(value)
	if err == nil {
		if seconds < 1 {
			seconds = 1
		}
		return time.Duration(seconds) * time.Second
	}

	if ts, err := http.ParseTime(value); err == nil {
		return maxDuration(time.Until(ts), time.Second)
	}

	return 0
}

func parseUnixTime(value string) time.Time {
	if value == "" {
		return time.Time{}
	}

	sec, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return time.Time{}
	}

	return time.Unix(sec, 0).UTC()
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

func runGoRemediation(
	ctx context.Context,
	cfg Config,
	projectDir string,
	patterns []string,
	owner, name string,
	client *github.Client,
	stdout, stderr io.Writer,
) error {
	if err := ensureModuleDir(projectDir); err != nil {
		return err
	}
	previousPlan := ""
	var lastAlerts []*github.DependabotAlert

	for iteration := 1; iteration <= cfg.MaxIterations; iteration++ {
		fmt.Fprintf(stdout, "Iteration %d/%d\n", iteration, cfg.MaxIterations)

		scan, err := runGovulncheck(ctx, projectDir, patterns)
		if err != nil {
			return err
		}

		alerts, err := listDependabotAlerts(ctx, client, owner, name)
		if err != nil {
			return err
		}
		lastAlerts = alerts

		targets, unsupported := collectTargets(scan, alerts)
		reportableTargets := sortTargets(targets)

		fmt.Fprintf(stdout, "  govulncheck vulnerabilities: %d\n", len(scan.UniqueOSVs))
		fmt.Fprintf(stdout, "  open Dependabot alerts: %d\n", len(alerts))
		fmt.Fprintf(stdout, "  actionable upgrades: %d\n", len(reportableTargets))

		if len(scan.UniqueOSVs) == 0 && len(alerts) == 0 {
			fmt.Fprintln(stdout, "All reported vulnerabilities are fixed.")
			return nil
		}

		if len(reportableTargets) == 0 {
			if len(unsupported) > 0 {
				fmt.Fprintln(stderr, "Unsupported findings:")
				for _, item := range unsupported {
					fmt.Fprintf(stderr, "  - %s\n", item)
				}
			}
			reportRemainingDependabotAlerts(stderr, alerts)
			return errors.New("vulnerabilities remain, but no actionable fixed versions were found")
		}

		planKey := renderPlanKey(reportableTargets)
		if planKey == previousPlan {
			fmt.Fprintln(stdout, "All fixable vulnerabilities have been addressed with the available upgrades.")
			reportRemainingUnfixable(stdout, stderr, scan, alerts, unsupported)
			return nil
		}
		previousPlan = planKey

		for _, target := range reportableTargets {
			fmt.Fprintf(stdout, "  - %s\n", describeTarget(target))
		}

		if cfg.DryRun {
			fmt.Fprintln(stdout, "Dry run complete; no changes were made.")
			return nil
		}

		if err := applyTargets(ctx, projectDir, reportableTargets, stdout, stderr); err != nil {
			return err
		}
	}

	reportRemainingDependabotAlerts(stderr, lastAlerts)
	return fmt.Errorf("reached max iterations (%d) before vulnerabilities were cleared", cfg.MaxIterations)
}

func discoverManifestDirs(root string) ([]string, []string, error) {
	goSet := make(map[string]struct{})
	npmSet := make(map[string]struct{})

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor":
				return filepath.SkipDir
			}
			return nil
		}

		dir := filepath.Dir(path)
		switch d.Name() {
		case "go.mod":
			goSet[dir] = struct{}{}
		case "package.json":
			npmSet[dir] = struct{}{}
		}

		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("discover manifests under %s: %w", root, err)
	}

	goDirs := make([]string, 0, len(goSet))
	for dir := range goSet {
		goDirs = append(goDirs, dir)
	}
	npmDirs := make([]string, 0, len(npmSet))
	for dir := range npmSet {
		npmDirs = append(npmDirs, dir)
	}

	sort.Strings(goDirs)
	sort.Strings(npmDirs)
	return goDirs, npmDirs, nil
}

func runNPMAuditFix(ctx context.Context, projectDir string, dryRun bool, stdout, stderr io.Writer) error {
	fmt.Fprintf(stdout, "npm remediation in %s\n", projectDir)
	if dryRun {
		fmt.Fprintln(stdout, "  dry-run: would run npm audit fix")
		return nil
	}
	return runNPM(ctx, projectDir, stdout, stderr, "audit", "fix")
}

func reportRemainingUnfixable(stdout, stderr io.Writer, scan *govScan, alerts []*github.DependabotAlert, unsupported []string) {
	if scan != nil && len(scan.UniqueOSVs) > 0 {
		fmt.Fprintf(stdout, "Unresolved govulncheck vulnerabilities: %d\n", len(scan.UniqueOSVs))
	}
	if len(unsupported) > 0 {
		fmt.Fprintln(stderr, "Unfixable findings:")
		for _, item := range unsupported {
			fmt.Fprintf(stderr, "  - %s\n", item)
		}
	}
	reportRemainingDependabotAlerts(stderr, alerts)
}

func reportRemainingDependabotAlerts(w io.Writer, alerts []*github.DependabotAlert) {
	if len(alerts) == 0 {
		return
	}

	fmt.Fprintf(w, "Dependabot alerts still open: %d\n", len(alerts))
	for _, alert := range alerts {
		if alert == nil {
			continue
		}
		module, version, alertID := dependabotTarget(alert)
		if module == "" {
			module = "unknown-package"
		}
		if version == "" {
			version = "unknown"
		}
		fmt.Fprintf(w, "  - %s %s (first patched: %s)\n", alertID, module, version)
	}
}

func ensureModuleDir(projectDir string) error {
	info, err := os.Stat(filepath.Join(projectDir, "go.mod"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%s does not contain go.mod", projectDir)
		}
		return fmt.Errorf("stat go.mod: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s/go.mod is a directory", projectDir)
	}
	return nil
}

func runGovulncheck(ctx context.Context, projectDir string, patterns []string) (*govScan, error) {
	args := append([]string{"-json"}, patterns...)
	cmd := exec.CommandContext(ctx, "govulncheck", args...)
	cmd.Dir = projectDir

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, errors.New("govulncheck was not found on PATH")
		}
		return nil, fmt.Errorf("govulncheck failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	dec := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	scan := &govScan{UniqueOSVs: make(map[string]struct{})}
	for dec.More() {
		var msg govulncheckMessage
		if err := dec.Decode(&msg); err != nil {
			return nil, fmt.Errorf("decode govulncheck output: %w", err)
		}
		if msg.Finding == nil {
			continue
		}
		scan.Findings = append(scan.Findings, msg.Finding)
		if msg.Finding.OSV != "" {
			scan.UniqueOSVs[msg.Finding.OSV] = struct{}{}
		}
	}

	return scan, nil
}

func listDependabotAlerts(ctx context.Context, client *github.Client, owner, repo string) ([]*github.DependabotAlert, error) {
	state := "open"
	ecosystem := "go"
	opts := &github.ListAlertsOptions{
		State:     ptr(state),
		Ecosystem: ptr(ecosystem),
	}
	opts.ListCursorOptions.PerPage = maxPerPage

	var all []*github.DependabotAlert
	for {
		alerts, resp, err := client.Dependabot.ListRepoAlerts(ctx, owner, repo, opts)
		if err != nil {
			return nil, fmt.Errorf("list Dependabot alerts for %s/%s: %w", owner, repo, err)
		}
		all = append(all, alerts...)
		if resp == nil || resp.After == "" {
			break
		}
		opts.ListCursorOptions.After = resp.After
	}

	return all, nil
}

func collectTargets(scan *govScan, alerts []*github.DependabotAlert) (map[string]*upgradeTarget, []string) {
	targets := make(map[string]*upgradeTarget)
	unsupported := make([]string, 0)

	for _, finding := range scan.Findings {
		if finding == nil || finding.FixedVersion == "" || len(finding.Trace) == 0 {
			continue
		}
		frame := finding.Trace[0]
		module := strings.TrimSpace(frame.Module)
		if module == "" {
			continue
		}

		if module == stdlibModule || module == toolchainModule {
			version := normalizeGoVersion(finding.FixedVersion)
			if version == "" {
				unsupported = append(unsupported, fmt.Sprintf("%s requires unsupported Go version %q", finding.OSV, finding.FixedVersion))
				continue
			}
			mergeTarget(targets, &upgradeTarget{
				Module:  "go",
				Version: version,
				Kind:    targetToolchain,
				Sources: map[string]struct{}{"govulncheck": {}},
				OSVs:    map[string]struct{}{finding.OSV: {}},
				Alerts:  map[string]struct{}{},
			})
			continue
		}

		version := normalizeModuleVersion(finding.FixedVersion)
		if version == "" {
			unsupported = append(unsupported, fmt.Sprintf("%s for %s has invalid fixed version %q", finding.OSV, module, finding.FixedVersion))
			continue
		}
		mergeTarget(targets, &upgradeTarget{
			Module:  module,
			Version: version,
			Kind:    targetModule,
			Sources: map[string]struct{}{"govulncheck": {}},
			OSVs:    map[string]struct{}{finding.OSV: {}},
			Alerts:  map[string]struct{}{},
		})
	}

	for _, alert := range alerts {
		if alert == nil {
			continue
		}
		module, version, alertID := dependabotTarget(alert)
		if module == "" || version == "" {
			unsupported = append(unsupported, fmt.Sprintf("Dependabot alert %s does not expose a patched version", alertID))
			continue
		}
		mergeTarget(targets, &upgradeTarget{
			Module:  module,
			Version: version,
			Kind:    targetModule,
			Sources: map[string]struct{}{"dependabot": {}},
			OSVs:    map[string]struct{}{},
			Alerts:  map[string]struct{}{alertID: {}},
		})
	}

	return targets, unsupported
}

func dependabotTarget(alert *github.DependabotAlert) (module, version, alertID string) {
	alertID = dependabotAlertID(alert)
	if alert.SecurityVulnerability != nil {
		if alert.SecurityVulnerability.Package != nil {
			module = strings.TrimSpace(alert.SecurityVulnerability.Package.GetName())
		}
		if alert.SecurityVulnerability.FirstPatchedVersion != nil {
			version = normalizeModuleVersion(alert.SecurityVulnerability.FirstPatchedVersion.GetIdentifier())
		}
	}
	if module == "" && alert.Dependency != nil && alert.Dependency.Package != nil {
		module = strings.TrimSpace(alert.Dependency.Package.GetName())
	}
	return module, version, alertID
}

func mergeTarget(targets map[string]*upgradeTarget, incoming *upgradeTarget) {
	key := string(incoming.Kind) + ":" + incoming.Module
	existing, ok := targets[key]
	if !ok {
		targets[key] = incoming
		return
	}

	if compareVersions(incoming.Kind, incoming.Version, existing.Version) > 0 {
		existing.Version = incoming.Version
	}
	mergeSet(existing.Sources, incoming.Sources)
	mergeSet(existing.OSVs, incoming.OSVs)
	mergeSet(existing.Alerts, incoming.Alerts)
}

func mergeSet(dst, src map[string]struct{}) {
	for key := range src {
		dst[key] = struct{}{}
	}
}

func compareVersions(kind targetKind, left, right string) int {
	if left == right {
		return 0
	}
	if kind == targetToolchain {
		left = normalizeForCompare(left)
		right = normalizeForCompare(right)
	}
	if left == "" || right == "" {
		if left > right {
			return 1
		}
		return -1
	}
	return semver.Compare(left, right)
}

func sortTargets(targets map[string]*upgradeTarget) []*upgradeTarget {
	ordered := make([]*upgradeTarget, 0, len(targets))
	for _, target := range targets {
		ordered = append(ordered, target)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Kind != ordered[j].Kind {
			return ordered[i].Kind < ordered[j].Kind
		}
		return ordered[i].Module < ordered[j].Module
	})
	return ordered
}

func renderPlanKey(targets []*upgradeTarget) string {
	parts := make([]string, 0, len(targets))
	for _, target := range targets {
		parts = append(parts, string(target.Kind)+":"+target.Module+"@"+target.Version)
	}
	return strings.Join(parts, ",")
}

func describeTarget(target *upgradeTarget) string {
	sources := make([]string, 0, len(target.Sources))
	for source := range target.Sources {
		sources = append(sources, source)
	}
	sort.Strings(sources)
	return fmt.Sprintf("%s@%s via %s", target.Module, target.Version, strings.Join(sources, ", "))
}

func applyTargets(ctx context.Context, projectDir string, targets []*upgradeTarget, stdout, stderr io.Writer) error {
	for _, target := range targets {
		arg := target.Module + "@" + target.Version
		if target.Kind == targetToolchain {
			arg = "go@" + target.Version
		}
		fmt.Fprintf(stdout, "  applying go get %s\n", arg)
		if err := runGo(ctx, projectDir, stdout, stderr, "get", arg); err != nil {
			return err
		}
	}

	fmt.Fprintln(stdout, "  running go mod tidy")
	if err := runGo(ctx, projectDir, stdout, stderr, "mod", "tidy"); err != nil {
		return err
	}

	fmt.Fprintln(stdout, "  running go mod vendor")
	if err := runGo(ctx, projectDir, stdout, stderr, "mod", "vendor"); err != nil {
		return err
	}

	return nil
}

func runGo(ctx context.Context, projectDir string, stdout, stderr io.Writer, args ...string) error {
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = projectDir
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return errors.New("go executable was not found on PATH")
		}
		return fmt.Errorf("go %s failed: %w", strings.Join(args, " "), err)
	}
	return nil
}

func runNPM(ctx context.Context, projectDir string, stdout, stderr io.Writer, args ...string) error {
	cmd := exec.CommandContext(ctx, "npm", args...)
	cmd.Dir = projectDir
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return errors.New("npm executable was not found on PATH")
		}
		return fmt.Errorf("npm %s failed: %w", strings.Join(args, " "), err)
	}
	return nil
}

func detectRepoFromGit(ctx context.Context, projectDir string) (string, error) {
	// Try origin first as the conventional primary remote.
	if out, err := gitRemoteURL(ctx, projectDir, "origin"); err == nil {
		if repo, err := parseGitHubRepo(out); err == nil {
			return repo, nil
		}
	}

	// Fall back to scanning every remote for any GitHub URL.
	listCmd := exec.CommandContext(ctx, "git", "remote")
	listCmd.Dir = projectDir
	listOut, err := listCmd.Output()
	if err != nil {
		return "", errNoRepoInfo
	}
	for remote := range strings.FieldsSeq(string(listOut)) {
		if remote == "origin" {
			continue // already tried
		}
		if out, err := gitRemoteURL(ctx, projectDir, remote); err == nil {
			if repo, err := parseGitHubRepo(out); err == nil {
				return repo, nil
			}
		}
	}
	return "", errNoRepoInfo
}

func gitRemoteURL(ctx context.Context, projectDir, remote string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", "remote", "get-url", remote)
	cmd.Dir = projectDir
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func splitRepo(repo string) (string, string, error) {
	parts := strings.Split(strings.TrimSpace(repo), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid repo %q, want owner/repo", repo)
	}
	return parts[0], parts[1], nil
}

func parseGitHubRepo(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if match := sshRepoPattern.FindStringSubmatch(value); len(match) == 3 {
		return match[1] + "/" + match[2], nil
	}
	if match := httpsRepoPattern.FindStringSubmatch(value); len(match) == 3 {
		return match[1] + "/" + match[2], nil
	}
	return "", fmt.Errorf("unsupported github remote %q", raw)
}

func normalizeModuleVersion(version string) string {
	trimmed := strings.TrimSpace(version)
	if trimmed == "" {
		return ""
	}
	if !strings.HasPrefix(trimmed, "v") {
		trimmed = "v" + trimmed
	}
	if !semver.IsValid(trimmed) {
		return ""
	}
	return trimmed
}

func normalizeGoVersion(version string) string {
	trimmed := strings.TrimSpace(version)
	if trimmed == "" {
		return ""
	}
	trimmed = strings.TrimPrefix(trimmed, "go")
	if normalized := normalizeModuleVersion(trimmed); normalized != "" {
		return strings.TrimPrefix(normalized, "v")
	}
	return ""
}

func normalizeForCompare(version string) string {
	if strings.HasPrefix(version, "v") {
		return version
	}
	return normalizeModuleVersion(version)
}

func dependabotAlertID(alert *github.DependabotAlert) string {
	if alert == nil {
		return "unknown"
	}
	if number := alert.GetNumber(); number != 0 {
		return fmt.Sprintf("#%d", number)
	}
	if url := strings.TrimSpace(alert.GetHTMLURL()); url != "" {
		return url
	}
	return "unknown"
}
