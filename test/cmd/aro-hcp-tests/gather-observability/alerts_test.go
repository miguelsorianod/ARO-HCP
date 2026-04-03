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
	"time"

	"k8s.io/utils/ptr"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/alertsmanagement/armalertsmanagement"
)

func TestToAlertSummary(t *testing.T) {
	t.Parallel()
	firedAt := time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC)
	resolvedAt := time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC)

	tests := []struct {
		name  string
		alert *armalertsmanagement.Alert
		want  AlertSummary
	}{
		{
			name: "nil Properties returns name only",
			alert: &armalertsmanagement.Alert{
				Name:       ptr.To("test-alert"),
				Properties: nil,
			},
			want: AlertSummary{
				Name: "test-alert",
			},
		},
		{
			name: "nil Essentials returns name only",
			alert: &armalertsmanagement.Alert{
				Name: ptr.To("test-alert"),
				Properties: &armalertsmanagement.AlertProperties{
					Essentials: nil,
				},
			},
			want: AlertSummary{
				Name: "test-alert",
			},
		},
		{
			name: "nil Name results in empty name",
			alert: &armalertsmanagement.Alert{
				Name:       nil,
				Properties: nil,
			},
			want: AlertSummary{},
		},
		{
			name: "fully populated alert with valid ARM resource ID extracts workspace",
			alert: &armalertsmanagement.Alert{
				Name: ptr.To("full-alert"),
				Properties: &armalertsmanagement.AlertProperties{
					Essentials: &armalertsmanagement.Essentials{
						Severity:                         ptr.To(armalertsmanagement.Severity("Sev2")),
						AlertState:                       ptr.To(armalertsmanagement.AlertState("New")),
						MonitorCondition:                 ptr.To(armalertsmanagement.MonitorCondition("Fired")),
						StartDateTime:                    &firedAt,
						MonitorConditionResolvedDateTime: &resolvedAt,
						Description:                      ptr.To("Test description"),
						AlertRule:                        ptr.To("/subscriptions/sub/providers/rules/myRule"),
						TargetResource:                   ptr.To("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Monitor/accounts/myWorkspace"),
						SignalType:                       ptr.To(armalertsmanagement.SignalType("Metric")),
					},
				},
			},
			want: AlertSummary{
				Name:           "full-alert",
				Severity:       "Sev2",
				State:          "New",
				Condition:      "Fired",
				FiredAt:        &firedAt,
				ResolvedAt:     &resolvedAt,
				Description:    "Test description",
				AlertRule:      "/subscriptions/sub/providers/rules/myRule",
				TargetResource: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Monitor/accounts/myWorkspace",
				SignalType:     "Metric",
				Workspace:      "myWorkspace",
			},
		},
		{
			name: "partial fields - only severity and state",
			alert: &armalertsmanagement.Alert{
				Name: ptr.To("partial-alert"),
				Properties: &armalertsmanagement.AlertProperties{
					Essentials: &armalertsmanagement.Essentials{
						Severity:   ptr.To(armalertsmanagement.Severity("Sev1")),
						AlertState: ptr.To(armalertsmanagement.AlertState("Acknowledged")),
					},
				},
			},
			want: AlertSummary{
				Name:     "partial-alert",
				Severity: "Sev1",
				State:    "Acknowledged",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := toAlertSummary(tt.alert)
			if got.Name != tt.want.Name {
				t.Errorf("Name = %q, want %q", got.Name, tt.want.Name)
			}
			if got.Severity != tt.want.Severity {
				t.Errorf("Severity = %q, want %q", got.Severity, tt.want.Severity)
			}
			if got.State != tt.want.State {
				t.Errorf("State = %q, want %q", got.State, tt.want.State)
			}
			if got.Condition != tt.want.Condition {
				t.Errorf("Condition = %q, want %q", got.Condition, tt.want.Condition)
			}
			if got.Description != tt.want.Description {
				t.Errorf("Description = %q, want %q", got.Description, tt.want.Description)
			}
			if got.AlertRule != tt.want.AlertRule {
				t.Errorf("AlertRule = %q, want %q", got.AlertRule, tt.want.AlertRule)
			}
			if got.TargetResource != tt.want.TargetResource {
				t.Errorf("TargetResource = %q, want %q", got.TargetResource, tt.want.TargetResource)
			}
			if got.SignalType != tt.want.SignalType {
				t.Errorf("SignalType = %q, want %q", got.SignalType, tt.want.SignalType)
			}
			if got.Workspace != tt.want.Workspace {
				t.Errorf("Workspace = %q, want %q", got.Workspace, tt.want.Workspace)
			}
			if (got.FiredAt == nil) != (tt.want.FiredAt == nil) {
				t.Errorf("FiredAt nil mismatch: got %v, want %v", got.FiredAt, tt.want.FiredAt)
			} else if got.FiredAt != nil && !got.FiredAt.Equal(*tt.want.FiredAt) {
				t.Errorf("FiredAt = %v, want %v", *got.FiredAt, *tt.want.FiredAt)
			}
			if (got.ResolvedAt == nil) != (tt.want.ResolvedAt == nil) {
				t.Errorf("ResolvedAt nil mismatch: got %v, want %v", got.ResolvedAt, tt.want.ResolvedAt)
			} else if got.ResolvedAt != nil && !got.ResolvedAt.Equal(*tt.want.ResolvedAt) {
				t.Errorf("ResolvedAt = %v, want %v", *got.ResolvedAt, *tt.want.ResolvedAt)
			}
		})
	}
}
