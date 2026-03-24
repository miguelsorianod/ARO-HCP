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

package arm

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armlocks"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
)

func TestNewDeletionStep_ReturnsErrorForInvalidConfig(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		mutate func(*DeletionStepConfig)
	}{
		{
			name: "neither included nor excluded",
			mutate: func(cfg *DeletionStepConfig) {
				cfg.Selector = ResourceSelector{}
			},
		},
		{
			name: "both included and excluded",
			mutate: func(cfg *DeletionStepConfig) {
				cfg.Selector = ResourceSelector{
					IncludedResourceTypes: []string{"typeA"},
					ExcludedResourceTypes: []string{"typeB"},
				}
			},
		},
		{
			name: "missing api version cache",
			mutate: func(cfg *DeletionStepConfig) {
				cfg.APIVersionCache = nil
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := validDeletionStepConfig()
			tc.mutate(&cfg)
			if _, err := NewDeletionStep(cfg); err == nil {
				t.Fatalf("expected config validation error")
			}
		})
	}
}

func TestMustNewDeletionStep_PanicsWhenConfigInvalid(t *testing.T) {
	t.Parallel()

	cfg := validDeletionStepConfig()
	cfg.APIVersionCache = nil

	defer func() {
		if recover() == nil {
			t.Fatalf("expected panic for invalid config")
		}
	}()
	_ = MustNewDeletionStep(cfg)
}

func TestNewDeletionStep_DefaultNameSelection(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		selector ResourceSelector
		wantName string
	}{
		{
			name: "single included type",
			selector: ResourceSelector{
				IncludedResourceTypes: []string{"Microsoft.Network/privateEndpoints"},
			},
			wantName: "Delete Microsoft.Network/privateEndpoints",
		},
		{
			name: "multiple included types",
			selector: ResourceSelector{
				IncludedResourceTypes: []string{"typeA", "typeB"},
			},
			wantName: "Delete selected resources",
		},
		{
			name: "excluded types",
			selector: ResourceSelector{
				ExcludedResourceTypes: []string{"typeA"},
			},
			wantName: "Delete resources excluding selected types",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := validDeletionStepConfig()
			cfg.Selector = tc.selector
			step, err := NewDeletionStep(cfg)
			if err != nil {
				t.Fatalf("expected constructor to succeed, got error: %v", err)
			}
			if got := step.Name(); got != tc.wantName {
				t.Fatalf("expected %q, got %q", tc.wantName, got)
			}
		})
	}
}

func TestNewDeletionStep_ExecutionOptions(t *testing.T) {
	t.Parallel()

	defaultCfg := validDeletionStepConfig()
	defaultCfg.Retries = 0
	defaultCfg.ContinueOnError = true
	stepWithDefaults, err := NewDeletionStep(defaultCfg)
	if err != nil {
		t.Fatalf("expected constructor to succeed, got error: %v", err)
	}
	if got := stepWithDefaults.RetryLimit(); got != 1 {
		t.Fatalf("expected default retry limit 1, got %d", got)
	}
	if got := stepWithDefaults.ContinueOnError(); !got {
		t.Fatalf("expected continueOnError true, got %t", got)
	}

	retryCfg := validDeletionStepConfig()
	retryCfg.Retries = 5
	retryCfg.ContinueOnError = false
	stepWithRetries, err := NewDeletionStep(retryCfg)
	if err != nil {
		t.Fatalf("expected constructor to succeed, got error: %v", err)
	}
	if got := stepWithRetries.RetryLimit(); got != 5 {
		t.Fatalf("expected retry limit 5, got %d", got)
	}
	if got := stepWithRetries.ContinueOnError(); got {
		t.Fatalf("expected continueOnError false, got %t", got)
	}
}

func validDeletionStepConfig() DeletionStepConfig {
	return DeletionStepConfig{
		ResourceGroupName: "rg",
		Client:            &armresources.Client{},
		LocksClient:       &armlocks.ManagementLocksClient{},
		APIVersionCache:   NewAPIVersionCache(nil),
		Selector: ResourceSelector{
			IncludedResourceTypes: []string{"Microsoft.Network/privateEndpoints"},
		},
	}
}
