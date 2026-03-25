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

package resourcegroup

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/Azure/ARO-HCP/tooling/cleanup-sweeper/pkg/policy"
)

func TestDiscoverCandidates(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		opts        RunOptions
		expectErr   bool
		errContains string
		want        []string
	}{
		{
			name: "explicit-only candidates are sorted",
			opts: RunOptions{
				ResourceGroups: sets.New("rg-b", "rg-a"),
				Policy: policy.RGOrderedPolicy{
					Discovery: policy.RGDiscoveryPolicy{},
				},
			},
			expectErr: false,
			want:      []string{"rg-a", "rg-b"},
		},
		{
			name: "policy discovery requires reference time when rules are configured",
			opts: RunOptions{
				ResourceGroups: sets.New[string](),
				ReferenceTime:  time.Time{},
				Policy: policy.RGOrderedPolicy{
					Discovery: policy.RGDiscoveryPolicy{
						Rules: []policy.RGDiscoveryRule{
							{
								Action:    policy.RGDiscoveryActionDelete,
								Match:     policy.RGDiscoveryMatch{Any: true},
								OlderThan: time.Hour,
							},
						},
					},
				},
			},
			expectErr:   true,
			errContains: "reference time is required",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := logr.NewContext(context.Background(), logr.Discard())
			got, err := discoverCandidates(ctx, tc.opts)
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				if tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("expected %d resource groups, got %d", len(tc.want), len(got))
			}
			for idx := range tc.want {
				if got[idx] != tc.want[idx] {
					t.Fatalf("expected sorted resource groups %v, got %v", tc.want, got)
				}
			}
		})
	}
}
