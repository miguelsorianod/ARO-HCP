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

package framework

import configv1 "github.com/openshift/api/config/v1"

// ClusterVersionHistoryEntrySummary is a compact view of one ClusterVersion status.history entry.
// Prefer SummarizeClusterVersionHistory over using raw []UpdateHistory where values are formatted
// for output (see SummarizeClusterVersionHistory).
type ClusterVersionHistoryEntrySummary struct {
	Version string `json:"version"`
	State   string `json:"state"`
	Image   string `json:"image"`
}

// SummarizeClusterVersionHistory returns a representation of ClusterVersion status.history entries
// that omits *metav1.Time fields from configv1.UpdateHistory, avoiding nil pointer panics when the
// result is logged (for example CompletionTime is nil when state is "Partial") that the GinkgoLogr
// formatter would hit when logging raw history in test output.
func SummarizeClusterVersionHistory(history []configv1.UpdateHistory) []ClusterVersionHistoryEntrySummary {
	out := make([]ClusterVersionHistoryEntrySummary, 0, len(history))
	for _, h := range history {
		out = append(out, ClusterVersionHistoryEntrySummary{
			Version: h.Version,
			State:   string(h.State),
			Image:   h.Image,
		})
	}
	return out
}
