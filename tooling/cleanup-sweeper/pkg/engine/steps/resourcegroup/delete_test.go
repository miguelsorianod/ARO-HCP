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
	"testing"

	"github.com/go-logr/logr"

	"github.com/Azure/ARO-HCP/tooling/cleanup-sweeper/pkg/engine/runner"
)

func TestDeleteStepConfig_StepOptions(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name              string
		cfg               DeleteStepConfig
		expectDiscoverErr bool
		wantStepName      string
		wantTargetName    string
	}{
		{
			name: "step options projection and default discover failure",
			cfg: DeleteStepConfig{
				Name:            "custom-name",
				Retries:         3,
				ContinueOnError: true,
			},
			expectDiscoverErr: true,
			wantStepName:      "custom-name",
		},
		{
			name:              "default step name",
			cfg:               DeleteStepConfig{},
			expectDiscoverErr: true,
			wantStepName:      "Delete resource group",
		},
		{
			name:              "discover returns target",
			cfg:               DeleteStepConfig{ResourceGroupName: "rg-example"},
			expectDiscoverErr: false,
			wantStepName:      "Delete resource group",
			wantTargetName:    "rg-example",
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

			step := NewDeleteStep(tc.cfg)
			if got := step.Name(); got != tc.wantStepName {
				t.Fatalf("expected step name %q, got %q", tc.wantStepName, got)
			}

			ctx := runner.ContextWithLogger(context.Background(), logr.Discard())
			targets, err := step.Discover(ctx)
			if tc.expectDiscoverErr {
				if err == nil {
					t.Fatalf("expected discover error")
				}
				return
			}
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if len(targets) != 1 {
				t.Fatalf("expected 1 target, got %d", len(targets))
			}
			if targets[0].Name != tc.wantTargetName {
				t.Fatalf("unexpected target name %q", targets[0].Name)
			}
			if targets[0].Type != ResourceType {
				t.Fatalf("unexpected target type %q", targets[0].Type)
			}
		})
	}
}
