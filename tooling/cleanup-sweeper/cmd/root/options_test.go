// Copyright 2026 Microsoft Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package root

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testPolicyYAML = `
rgOrdered:
  discovery:
    rules:
      - action: delete
        match:
          any: true
        olderThan: "1h"
`

func TestRawOptionsValidate_RGOrderedRejectsWhitespaceOnlyResourceGroup(t *testing.T) {
	t.Parallel()

	policyPath := writePolicyFile(t)
	testCases := []struct {
		name        string
		opts        RawOptions
		expectErr   bool
		errContains string
	}{
		{
			name: "rg-ordered accepts whitespace-only resource group and relies on policy discovery",
			opts: RawOptions{
				SubscriptionID: "sub-id",
				Workflow:       string(WorkflowRGOrdered),
				PolicyFile:     policyPath,
				DryRun:         true,
				Parallelism:    1,
				ResourceGroups: []string{"   "},
			},
			expectErr: false,
		},
		{
			name: "rg-ordered allows trimmed non-empty resource group",
			opts: RawOptions{
				SubscriptionID: "sub-id",
				Workflow:       string(WorkflowRGOrdered),
				PolicyFile:     policyPath,
				DryRun:         true,
				Parallelism:    1,
				ResourceGroups: []string{"   rg-one   "},
			},
			expectErr: false,
		},
		{
			name: "shared-leftovers ignores whitespace selectors",
			opts: RawOptions{
				SubscriptionID: "sub-id",
				Workflow:       string(WorkflowSharedLeftovers),
				DryRun:         true,
				Parallelism:    1,
				ResourceGroups: []string{"   "},
			},
			expectErr: false,
		},
		{
			name: "shared-leftovers rejects explicit rg selectors",
			opts: RawOptions{
				SubscriptionID: "sub-id",
				Workflow:       string(WorkflowSharedLeftovers),
				DryRun:         true,
				Parallelism:    1,
				ResourceGroups: []string{"rg-one"},
			},
			expectErr:   true,
			errContains: "rg-ordered selectors are not allowed for shared-leftovers workflow",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := tc.opts.Validate(context.Background())
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected validation error")
				}
				if tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}

			if err != nil {
				t.Fatalf("expected validation success, got %v", err)
			}
		})
	}
}

func writePolicyFile(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(testPolicyYAML), 0o600); err != nil {
		t.Fatalf("failed to write policy file: %v", err)
	}
	return path
}
