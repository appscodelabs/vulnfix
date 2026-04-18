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
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-github/v84/github"
)

func TestParseGitHubRepo(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "https", input: "https://github.com/acme/project.git", want: "acme/project"},
		{name: "https no git", input: "https://github.com/acme/project", want: "acme/project"},
		{name: "ssh", input: "git@github.com:acme/project.git", want: "acme/project"},
		{name: "ssh url", input: "ssh://git@github.com/acme/project.git", want: "acme/project"},
		{name: "invalid", input: "https://example.com/acme/project.git", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseGitHubRepo(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseGitHubRepo returned error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("parseGitHubRepo(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestCollectTargets(t *testing.T) {
	t.Parallel()

	scan := &govScan{
		UniqueOSVs: map[string]struct{}{"GO-1234": {}},
		Findings: []*govulncheckFinding{
			{
				OSV:          "GO-1234",
				FixedVersion: "1.2.3",
				Trace:        []govulncheckFrame{{Module: "github.com/example/mod"}},
			},
			{
				OSV:          "GO-9999",
				FixedVersion: "1.22.5",
				Trace:        []govulncheckFrame{{Module: stdlibModule}},
			},
		},
	}

	alert := &github.DependabotAlert{
		Number: ptr(42),
		SecurityVulnerability: &github.AdvisoryVulnerability{
			Package:             &github.VulnerabilityPackage{Name: ptr("github.com/example/other")},
			FirstPatchedVersion: &github.FirstPatchedVersion{Identifier: ptr("v2.3.4")},
		},
	}

	targets, unsupported := collectTargets(scan, []*github.DependabotAlert{alert})
	if len(unsupported) != 0 {
		t.Fatalf("collectTargets returned unsupported entries: %v", unsupported)
	}

	ordered := sortTargets(targets)
	if len(ordered) != 3 {
		t.Fatalf("expected 3 targets, got %d", len(ordered))
	}

	if got := ordered[0].Module + "@" + ordered[0].Version; got != "github.com/example/mod@v1.2.3" {
		t.Fatalf("unexpected first target %q", got)
	}
	if got := ordered[1].Module + "@" + ordered[1].Version; got != "github.com/example/other@v2.3.4" {
		t.Fatalf("unexpected second target %q", got)
	}
	if got := ordered[2].Module + "@" + ordered[2].Version; got != "go@1.22.5" {
		t.Fatalf("unexpected third target %q", got)
	}
}

func TestRunDryRunRequiresRepoAndToken(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	err := Run(context.Background(), Config{
		ProjectDir:  ".",
		Repo:        "",
		GitHubToken: "",
		EnableGo:    true,
		EnableNPM:   false,
		DryRun:      true,
		Stdout:      &stdout,
	})
	if err == nil {
		t.Fatal("expected error when repo and token are missing")
	}
}

func TestRunEmptyProjectDirUsesCurrentDirectory(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	t.Chdir(filepath.Join(filepath.Dir(file), "..", ".."))

	var stdout bytes.Buffer
	err := Run(context.Background(), Config{
		ProjectDir:  "",
		Repo:        "",
		GitHubToken: "",
		EnableGo:    true,
		EnableNPM:   false,
		DryRun:      true,
		Stdout:      &stdout,
	})
	if err != nil && strings.Contains(err.Error(), "does not contain go.mod") {
		t.Fatalf("Run resolved the wrong current directory: %v", err)
	}
}

func TestRunRequiresAtLeastOneEcosystem(t *testing.T) {
	t.Parallel()

	err := Run(context.Background(), Config{
		ProjectDir: ".",
		EnableGo:   false,
		EnableNPM:  false,
	})
	if err == nil {
		t.Fatal("expected an ecosystem selection error")
	}
}
