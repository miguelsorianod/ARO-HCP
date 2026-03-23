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

package network

import "testing"

func TestNSPForceDeleteStepConfig_StepOptions(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		cfg          NSPForceDeleteStepConfig
		wantStepName string
	}{
		{
			name: "step options projection",
			cfg: NSPForceDeleteStepConfig{
				Name:            "custom-name",
				Retries:         2,
				ContinueOnError: true,
			},
			wantStepName: "custom-name",
		},
		{
			name:         "default step name",
			cfg:          NSPForceDeleteStepConfig{},
			wantStepName: "Delete network security perimeters",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := tc.cfg.StepOptions()
			if tc.cfg.Name != "" && opts.Name != tc.cfg.Name {
				t.Fatalf("expected name %q, got %q", tc.cfg.Name, opts.Name)
			}
			if opts.Retries != tc.cfg.Retries {
				t.Fatalf("expected retries %d, got %d", tc.cfg.Retries, opts.Retries)
			}
			if opts.ContinueOnError != tc.cfg.ContinueOnError {
				t.Fatalf("expected continueOnError %t, got %t", tc.cfg.ContinueOnError, opts.ContinueOnError)
			}

			step := NewNSPForceDeleteStep(tc.cfg)
			if got := step.Name(); got != tc.wantStepName {
				t.Fatalf("expected step name %q, got %q", tc.wantStepName, got)
			}
		})
	}
}
