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

package arm

import (
	"context"
	"strings"
	"testing"
)

func TestAPIVersionCacheGet(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name       string
		setup      func(cache *APIVersionCache)
		resource   string
		assertions func(t *testing.T, got string, err error)
	}

	testCases := []testCase{
		{
			name: "get returns cached value set with normalization",
			setup: func(cache *APIVersionCache) {
				cache.Set(" Microsoft.Network/virtualNetworks ", " 2024-03-01 ")
			},
			resource: "microsoft.network/virtualnetworks",
			assertions: func(t *testing.T, got string, err error) {
				t.Helper()
				if err != nil {
					t.Fatalf("expected cached API version, got error: %v", err)
				}
				if got != "2024-03-01" {
					t.Fatalf("expected API version %q, got %q", "2024-03-01", got)
				}
			},
		},
		{
			name:     "get miss without providers client fails",
			resource: "Microsoft.Network/publicIPAddresses",
			assertions: func(t *testing.T, _ string, err error) {
				t.Helper()
				if err == nil {
					t.Fatal("expected error on cache miss without providers client")
				}
				if !strings.Contains(err.Error(), "providers client is required") {
					t.Fatalf("expected providers client error, got: %v", err)
				}
			},
		},
		{
			name:     "get rejects empty resource type",
			resource: "  ",
			assertions: func(t *testing.T, _ string, err error) {
				t.Helper()
				if err == nil {
					t.Fatal("expected error for empty resource type")
				}
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cache := NewAPIVersionCache(nil)
			if tc.setup != nil {
				tc.setup(cache)
			}
			got, err := cache.Get(context.Background(), tc.resource)
			tc.assertions(t, got, err)
		})
	}
}
