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
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/alertsmanagement/armalertsmanagement"
)

type severityInfo struct {
	CSSClass string
}

// severityRanks maps each SDK severity to its ordinal position (0 = most
// critical). Built once from PossibleSeverityValues() so it stays in sync
// with the SDK.
var severityRanks = func() map[armalertsmanagement.Severity]int {
	m := make(map[armalertsmanagement.Severity]int)
	for i, s := range armalertsmanagement.PossibleSeverityValues() {
		m[s] = i
	}
	return m
}()

var severityDisplay = map[armalertsmanagement.Severity]severityInfo{
	armalertsmanagement.SeveritySev0: {CSSClass: "severity-critical"},
	armalertsmanagement.SeveritySev1: {CSSClass: "severity-error"},
	armalertsmanagement.SeveritySev2: {CSSClass: "severity-warning"},
	armalertsmanagement.SeveritySev3: {CSSClass: "severity-info"},
	armalertsmanagement.SeveritySev4: {CSSClass: "severity-verbose"},
}

// severityRank returns the numeric rank for a severity value (Sev0=0 .. Sev4=4).
// Returns -1 for unknown severities.
func severityRank(sev armalertsmanagement.Severity) int {
	if r, ok := severityRanks[sev]; ok {
		return r
	}
	return -1
}

// severityCSSClass returns the CSS class name for a severity value.
func severityCSSClass(sev armalertsmanagement.Severity) string {
	if info, ok := severityDisplay[sev]; ok {
		return info.CSSClass
	}
	return "severity-verbose"
}

// ParseSeverityThreshold converts a severity string (e.g. "Sev2") to its
// numeric rank using the SDK's known severity values. Returns -1 (no filter)
// for empty input.
func ParseSeverityThreshold(s string) (int, error) {
	if s == "" {
		return -1, nil
	}
	sev := armalertsmanagement.Severity(s)
	r := severityRank(sev)
	if r < 0 {
		return 0, fmt.Errorf("unknown severity %q, expected one of %v", s, armalertsmanagement.PossibleSeverityValues())
	}
	return r, nil
}

// filterAlertsBySeverity returns only the alerts whose severity rank is at or
// below the given threshold. A threshold of -1 means no filtering.
func filterAlertsBySeverity(alerts []AlertSummary, threshold int) []AlertSummary {
	if threshold < 0 {
		return alerts
	}
	filtered := make([]AlertSummary, 0, len(alerts))
	for _, a := range alerts {
		rank := severityRank(a.Severity)
		if rank >= 0 && rank <= threshold {
			filtered = append(filtered, a)
		}
	}
	return filtered
}
