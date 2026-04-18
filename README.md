# govulnfix

`govulnfix` is a CLI that recursively scans a project tree and applies
ecosystem-specific vulnerability fixes:

- For each directory containing `go.mod`, it runs iterative Go remediation
  using `govulncheck` and GitHub Dependabot alerts.
- For each directory containing `package.json`, it runs `npm audit fix`.

## How it works

1. Recursively finds all directories containing `go.mod` and `package.json`.
2. For each Go module directory:
  Runs `govulncheck -json ./...`, fetches open Dependabot Go alerts,
  applies `go get` upgrades, then runs `go mod tidy` and `go mod vendor`.
3. For each npm package directory:
  Runs `npm audit fix`.
4. Honors `--go` and `--npm` toggles to enable or disable ecosystems.

## Prerequisites

- Go toolchain with `govulncheck` installed (`go install golang.org/x/vuln/cmd/govulncheck@latest`) when `--go=true`
- Node.js and npm when `--npm=true`
- A GitHub personal access token (or fine-grained token) with **read** access to Dependabot alerts (`security_events` scope for classic tokens) when `--go=true`

## Installation

```sh
go install github.com/appscodelabs/govulnfix@latest
```

## Usage

```
govulnfix [flags]

Flags:
  --dir string            Root directory to recursively scan for go.mod and package.json (default: current directory)
  --go                    Enable Go vulnerability remediation (default: true)
  --npm                   Enable npm remediation via npm audit fix (default: true)
  --repo string           GitHub repository in owner/repo form
                          (defaults to GITHUB_REPOSITORY env var or the origin remote)
  --github-token string   GitHub token for Dependabot alerts
                          (defaults to GITHUB_TOKEN, then GH_TOOLS_TOKEN)
  --pattern strings       Package patterns passed to govulncheck (default: [./...])
  --max-iterations int    Maximum remediation passes to attempt (default: 10)
  --dry-run               Print planned upgrades without modifying go.mod
```

### Examples

Fix Go and npm vulnerabilities under the current tree:

```sh
export GITHUB_TOKEN=ghp_...
govulnfix
```

Target a specific module directory and repository:

```sh
govulnfix --dir ./myservice --repo myorg/myservice --github-token ghp_...
```

Run only npm fixes:

```sh
govulnfix --go=false --npm=true
```

Run only Go fixes:

```sh
govulnfix --go=true --npm=false
```

Preview the planned upgrades without making any changes:

```sh
govulnfix --dry-run
```

## GitHub repository detection

The `--repo` flag is resolved in the following order:

1. `--repo` flag value
2. `GITHUB_REPOSITORY` environment variable
3. `origin` remote URL parsed as a GitHub HTTPS or SSH URL
4. Any other `git remote` URL that points to GitHub

## Token detection

The `--github-token` flag is resolved in the following order:

1. `--github-token` flag value
2. `GITHUB_TOKEN` environment variable
3. `GH_TOOLS_TOKEN` environment variable

## License

[Apache 2.0](LICENSE)
