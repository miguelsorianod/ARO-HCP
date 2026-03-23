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

package roleassignments

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v3"
)

func TestEscapeODataString_EscapesSingleQuotes(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		in   string
		want string
		fn   func(string) string
	}{
		{
			name: "escape OData string single quotes",
			in:   "O'Hara Team",
			want: "O''Hara Team",
			fn:   escapeODataString,
		},
		{
			name: "normalize ID trims and lowercases",
			in:   "  /SUBSCRIPTIONS/ABC  ",
			want: "/subscriptions/abc",
			fn:   normalizeID,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.fn(tc.in); got != tc.want {
				t.Fatalf("expected %q, got %q", tc.want, got)
			}
		})
	}
}

func TestAssignmentWithinResourceGroupScope_UsesScopeWhenPresent(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		role *armauthorization.RoleAssignment
		want bool
	}{
		{
			name: "uses scope when present",
			role: &armauthorization.RoleAssignment{
				Properties: &armauthorization.RoleAssignmentProperties{
					Scope: strPtr("/subscriptions/abc/resourceGroups/rg-one/providers/Microsoft.Compute/virtualMachines/vm1"),
				},
			},
			want: true,
		},
		{
			name: "falls back to ID",
			role: &armauthorization.RoleAssignment{
				ID: strPtr("/subscriptions/abc/resourceGroups/rg-one/providers/Microsoft.Authorization/roleAssignments/ra1"),
			},
			want: true,
		},
		{
			name: "rejects non-RG scope",
			role: &armauthorization.RoleAssignment{
				Properties: &armauthorization.RoleAssignmentProperties{
					Scope: strPtr("/subscriptions/abc"),
				},
			},
			want: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := assignmentWithinResourceGroupScope(tc.role, "/subscriptions/abc/resourcegroups/")
			if got != tc.want {
				t.Fatalf("expected %t, got %t", tc.want, got)
			}
		})
	}
}

func TestToRoleAssignmentRecord_ReturnsFalseWithoutID(t *testing.T) {
	t.Parallel()

	if _, ok := toRoleAssignmentRecord(&armauthorization.RoleAssignment{}); ok {
		t.Fatalf("expected conversion to fail without ID")
	}
}

func TestRoleAssignmentName_FallsBackToID(t *testing.T) {
	t.Parallel()

	role := &armauthorization.RoleAssignment{
		ID:   strPtr("/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Authorization/roleAssignments/ra1"),
		Name: strPtr(""),
	}

	if got, want := roleAssignmentName(role, "fallback-id"), "fallback-id"; got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func strPtr(value string) *string { return &value }
