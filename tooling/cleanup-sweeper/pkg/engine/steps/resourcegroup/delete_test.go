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

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
)

func TestDeleteStepConfig_ExecutionOptions(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		cfg            DeleteStepConfig
		wantStepName   string
		wantTargetName string
	}{
		{
			name: "step options projection and discover success",
			cfg: DeleteStepConfig{
				ResourceGroupName: "rg-custom",
				RGClient:          &armresources.ResourceGroupsClient{},
				Name:              "custom-name",
				Retries:           3,
				ContinueOnError:   true,
			},
			wantStepName:   "custom-name",
			wantTargetName: "rg-custom",
		},
		{
			name: "default step name",
			cfg: DeleteStepConfig{
				ResourceGroupName: "rg-default",
				RGClient:          &armresources.ResourceGroupsClient{},
			},
			wantStepName:   "Delete resource group",
			wantTargetName: "rg-default",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			step, err := NewDeleteStep(tc.cfg)
			if err != nil {
				t.Fatalf("expected constructor to succeed, got error: %v", err)
			}
			if got := step.Name(); got != tc.wantStepName {
				t.Fatalf("expected step name %q, got %q", tc.wantStepName, got)
			}
			expectedRetryLimit := tc.cfg.Retries
			if expectedRetryLimit < 1 {
				expectedRetryLimit = 1
			}
			if got := step.RetryLimit(); got != expectedRetryLimit {
				t.Fatalf("expected retry limit %d, got %d", expectedRetryLimit, got)
			}
			if got := step.ContinueOnError(); got != tc.cfg.ContinueOnError {
				t.Fatalf("expected continueOnError %t, got %t", tc.cfg.ContinueOnError, got)
			}

			ctx := logr.NewContext(context.Background(), logr.Discard())
			targets, err := step.Discover(ctx)
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

func TestNewDeleteStep_ReturnsErrorWhenInvalid(t *testing.T) {
	t.Parallel()

	cfg := DeleteStepConfig{
		ResourceGroupName: "rg",
		RGClient:          nil,
	}
	if _, err := NewDeleteStep(cfg); err == nil {
		t.Fatalf("expected validation error for missing resource groups client")
	}
}

func TestMustNewDeleteStep_PanicsWhenInvalid(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Fatalf("expected panic for invalid config")
		}
	}()
	_ = MustNewDeleteStep(DeleteStepConfig{
		ResourceGroupName: "",
		RGClient:          &armresources.ResourceGroupsClient{},
	})
}
