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

import "testing"

func TestGoCheckFlagsDefaultEnabled(t *testing.T) {
	t.Parallel()

	cmd := newRootCmd()
	for _, name := range []string{"govulncheck", "dependabot"} {
		t.Run(name, func(t *testing.T) {
			flag := cmd.Flags().Lookup(name)
			if flag == nil {
				t.Fatalf("missing --%s flag", name)
			}
			if flag.DefValue != "true" {
				t.Errorf("--%s default = %q, want true", name, flag.DefValue)
			}
			if err := cmd.Flags().Set(name, "false"); err != nil {
				t.Fatalf("disable --%s: %v", name, err)
			}
			enabled, err := cmd.Flags().GetBool(name)
			if err != nil {
				t.Fatalf("read --%s: %v", name, err)
			}
			if enabled {
				t.Errorf("--%s remained enabled after setting false", name)
			}
		})
	}
}
