// Copyright 2025 Microsoft Corporation
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

package gatherobservability

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/alertsmanagement/armalertsmanagement"
)

func TestSeverityRank(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		severity armalertsmanagement.Severity
		want     int
	}{
		{name: "Sev0", severity: armalertsmanagement.SeveritySev0, want: 0},
		{name: "Sev1", severity: armalertsmanagement.SeveritySev1, want: 1},
		{name: "Sev2", severity: armalertsmanagement.SeveritySev2, want: 2},
		{name: "Sev3", severity: armalertsmanagement.SeveritySev3, want: 3},
		{name: "Sev4", severity: armalertsmanagement.SeveritySev4, want: 4},
		{name: "unknown severity", severity: "Critical", want: -1},
		{name: "empty string", severity: "", want: -1},
		{name: "lowercase sev0", severity: "sev0", want: -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := severityRank(tt.severity)
			if got != tt.want {
				t.Errorf("severityRank(%q) = %d, want %d", tt.severity, got, tt.want)
			}
		})
	}
}

func TestSeverityCSSClass(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		severity armalertsmanagement.Severity
		want     string
	}{
		{name: "Sev0 is critical", severity: armalertsmanagement.SeveritySev0, want: "severity-critical"},
		{name: "Sev1 is error", severity: armalertsmanagement.SeveritySev1, want: "severity-error"},
		{name: "Sev2 is warning", severity: armalertsmanagement.SeveritySev2, want: "severity-warning"},
		{name: "Sev3 is info", severity: armalertsmanagement.SeveritySev3, want: "severity-info"},
		{name: "Sev4 is verbose", severity: armalertsmanagement.SeveritySev4, want: "severity-verbose"},
		{name: "unknown returns verbose", severity: "SomeOther", want: "severity-verbose"},
		{name: "empty returns verbose", severity: "", want: "severity-verbose"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := severityCSSClass(tt.severity)
			if got != tt.want {
				t.Errorf("severityCSSClass(%q) = %q, want %q", tt.severity, got, tt.want)
			}
		})
	}
}

func TestParseSeverityThreshold(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		input   string
		want    int
		wantErr bool
	}{
		{name: "empty returns no filter", input: "", want: -1},
		{name: "Sev0", input: "Sev0", want: 0},
		{name: "Sev1", input: "Sev1", want: 1},
		{name: "Sev2", input: "Sev2", want: 2},
		{name: "Sev3", input: "Sev3", want: 3},
		{name: "Sev4", input: "Sev4", want: 4},
		{name: "invalid severity returns error", input: "Critical", wantErr: true},
		{name: "lowercase sev0 returns error", input: "sev0", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSeverityThreshold(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseSeverityThreshold(%q) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseSeverityThreshold(%q) unexpected error: %v", tt.input, err)
				return
			}
			if got != tt.want {
				t.Errorf("ParseSeverityThreshold(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestFilterAlertsBySeverity(t *testing.T) {
	t.Parallel()
	alerts := []AlertSummary{
		{Name: "critical-alert", Severity: armalertsmanagement.SeveritySev0},
		{Name: "error-alert", Severity: armalertsmanagement.SeveritySev1},
		{Name: "warning-alert", Severity: armalertsmanagement.SeveritySev2},
		{Name: "info-alert", Severity: armalertsmanagement.SeveritySev3},
		{Name: "verbose-alert", Severity: armalertsmanagement.SeveritySev4},
		{Name: "unknown-alert", Severity: "Unknown"},
	}

	tests := []struct {
		name      string
		alerts    []AlertSummary
		threshold int
		wantCount int
		wantNames []string
	}{
		{
			name:      "no filter returns all",
			alerts:    alerts,
			threshold: -1,
			wantCount: 6,
		},
		{
			name:      "threshold Sev2 includes Sev0 Sev1 Sev2",
			alerts:    alerts,
			threshold: 2,
			wantCount: 3,
			wantNames: []string{"critical-alert", "error-alert", "warning-alert"},
		},
		{
			name:      "threshold Sev0 includes only Sev0",
			alerts:    alerts,
			threshold: 0,
			wantCount: 1,
			wantNames: []string{"critical-alert"},
		},
		{
			name:      "threshold Sev4 includes all known severities",
			alerts:    alerts,
			threshold: 4,
			wantCount: 5,
			wantNames: []string{"critical-alert", "error-alert", "warning-alert", "info-alert", "verbose-alert"},
		},
		{
			name:      "empty alerts returns empty",
			alerts:    []AlertSummary{},
			threshold: 2,
			wantCount: 0,
		},
		{
			name:      "unknown severity is filtered out",
			alerts:    []AlertSummary{{Name: "unknown", Severity: "Unknown"}},
			threshold: 4,
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterAlertsBySeverity(tt.alerts, tt.threshold)
			if len(got) != tt.wantCount {
				t.Errorf("filterAlertsBySeverity() returned %d alerts, want %d", len(got), tt.wantCount)
			}
			if tt.wantNames != nil {
				for i, name := range tt.wantNames {
					if i >= len(got) {
						t.Errorf("missing expected alert at index %d: %s", i, name)
						continue
					}
					if got[i].Name != name {
						t.Errorf("alert[%d].Name = %q, want %q", i, got[i].Name, name)
					}
				}
			}
		})
	}
}
