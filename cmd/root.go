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

package cmd

import (
	"context"
	"os"

	"github.com/appscodelabs/vulnfix/internal/remediate"

	"github.com/spf13/cobra"
)

func Execute() error {
	return newRootCmd().Execute()
}

func newRootCmd() *cobra.Command {
	var cfg remediate.Config

	cmd := &cobra.Command{
		Use:   "vulnfix",
		Short: "Recursively remediate Go and npm vulnerabilities across a project tree",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg.Stdout = cmd.OutOrStdout()
			cfg.Stderr = cmd.ErrOrStderr()
			return remediate.Run(cmd.Context(), cfg)
		},
		SilenceUsage: true,
	}

	cmd.SetOut(os.Stdout)
	cmd.SetErr(os.Stderr)
	cmd.SetContext(context.Background())

	flags := cmd.Flags()
	flags.StringVar(&cfg.ProjectDir, "dir", ".", "Path to the Go module to update")
	flags.StringVar(&cfg.Repo, "repo", "", "GitHub repository in owner/repo form; defaults to GITHUB_REPOSITORY or origin remote")
	flags.StringVar(&cfg.GitHubToken, "github-token", "", "GitHub token with security_events or Dependabot alerts read access; defaults to GITHUB_TOKEN")
	flags.StringSliceVar(&cfg.Patterns, "pattern", []string{"./..."}, "Package patterns passed to govulncheck")
	flags.IntVar(&cfg.MaxIterations, "max-iterations", 10, "Maximum remediation passes to attempt")
	flags.BoolVar(&cfg.EnableGo, "go", true, "Enable Go vulnerability remediation for directories containing go.mod")
	flags.BoolVar(&cfg.EnableNPM, "npm", true, "Enable npm remediation (npm audit fix) for directories containing package.json")
	flags.BoolVar(&cfg.DryRun, "dry-run", false, "Print the planned module upgrades without changing go.mod")

	return cmd
}
