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

package common

import (
	"sort"

	"github.com/go-logr/logr"
)

// DiscoverySkipReporter records and reports why discovery candidates were skipped.
type DiscoverySkipReporter struct {
	step     string
	total    int
	byReason map[string]int
}

// NewDiscoverySkipReporter builds a reporter for a discovery step.
func NewDiscoverySkipReporter(step string) *DiscoverySkipReporter {
	return &DiscoverySkipReporter{
		step:     step,
		byReason: map[string]int{},
	}
}

// Record reports a skipped resource at V(1) and increments aggregate counters.
func (r *DiscoverySkipReporter) Record(logger logr.Logger, reason string, keysAndValues ...any) {
	r.total++
	r.byReason[reason]++

	kvs := []any{"step", r.step, "reason", reason}
	kvs = append(kvs, keysAndValues...)
	logger.V(1).Info("Skipping discovery candidate", kvs...)
}

// Flush emits aggregate skip counts at info level.
func (r *DiscoverySkipReporter) Flush(logger logr.Logger) {
	if r.total == 0 {
		return
	}

	reasons := make([]string, 0, len(r.byReason))
	for reason := range r.byReason {
		reasons = append(reasons, reason)
	}
	sort.Strings(reasons)

	for _, reason := range reasons {
		logger.Info(
			"Discovery skipped candidates",
			"step", r.step,
			"reason", reason,
			"count", r.byReason[reason],
		)
	}
}
