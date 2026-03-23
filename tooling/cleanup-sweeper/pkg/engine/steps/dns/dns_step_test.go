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

package dns

import "testing"

func TestParseNSRecordSetTargetID(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name              string
		id                string
		expectErr         bool
		wantSubscription  string
		wantResourceGroup string
		wantZoneName      string
		wantRecordSetName string
	}{
		{
			name:              "valid NS record set ID",
			id:                "/subscriptions/1d3378d3-5a3f-4712-85a1-2485495dfc4b/resourceGroups/global/providers/Microsoft.Network/dnszones/hcp.osadev.cloud/NS/usw3rvaz",
			expectErr:         false,
			wantSubscription:  "1d3378d3-5a3f-4712-85a1-2485495dfc4b",
			wantResourceGroup: "global",
			wantZoneName:      "hcp.osadev.cloud",
			wantRecordSetName: "usw3rvaz",
		},
		{
			name:      "invalid ID",
			id:        "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Network/dnszones",
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			subscriptionID, resourceGroup, zoneName, recordSetName, err := parseNSRecordSetTargetID(tc.id)
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected parse error")
				}
				return
			}
			if err != nil {
				t.Fatalf("expected parse to succeed, got error: %v", err)
			}
			if subscriptionID != tc.wantSubscription {
				t.Fatalf("unexpected subscriptionID: %q", subscriptionID)
			}
			if resourceGroup != tc.wantResourceGroup {
				t.Fatalf("unexpected resourceGroup: %q", resourceGroup)
			}
			if zoneName != tc.wantZoneName {
				t.Fatalf("unexpected zoneName: %q", zoneName)
			}
			if recordSetName != tc.wantRecordSetName {
				t.Fatalf("unexpected recordSetName: %q", recordSetName)
			}
		})
	}
}
