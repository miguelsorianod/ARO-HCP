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

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v8"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armlocks"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
)

func TestNSPForceDeleteStepConfig_ExecutionOptions(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		cfg          NSPForceDeleteStepConfig
		wantStepName string
	}{
		{
			name: "step options projection",
			cfg: NSPForceDeleteStepConfig{
				ResourceGroupName: "rg",
				ResourcesClient:   &armresources.Client{},
				LocksClient:       &armlocks.ManagementLocksClient{},
				NSPClient:         &armnetwork.SecurityPerimetersClient{},
				Name:              "custom-name",
				Retries:           2,
				ContinueOnError:   true,
			},
			wantStepName: "custom-name",
		},
		{
			name: "default step name",
			cfg: NSPForceDeleteStepConfig{
				ResourceGroupName: "rg",
				ResourcesClient:   &armresources.Client{},
				LocksClient:       &armlocks.ManagementLocksClient{},
				NSPClient:         &armnetwork.SecurityPerimetersClient{},
			},
			wantStepName: "Delete network security perimeters",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			step, err := NewNSPForceDeleteStep(tc.cfg)
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
		})
	}
}

func TestNewNSPForceDeleteStep_ReturnsErrorWhenInvalid(t *testing.T) {
	t.Parallel()

	cfg := NSPForceDeleteStepConfig{
		ResourceGroupName: "rg",
		ResourcesClient:   &armresources.Client{},
		LocksClient:       &armlocks.ManagementLocksClient{},
		NSPClient:         nil,
	}
	if _, err := NewNSPForceDeleteStep(cfg); err == nil {
		t.Fatalf("expected validation error for missing NSP client")
	}
}

func TestMustNewNSPForceDeleteStep_PanicsWhenInvalid(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Fatalf("expected panic for invalid config")
		}
	}()
	_ = MustNewNSPForceDeleteStep(NSPForceDeleteStepConfig{
		ResourceGroupName: "",
		ResourcesClient:   &armresources.Client{},
		LocksClient:       &armlocks.ManagementLocksClient{},
		NSPClient:         &armnetwork.SecurityPerimetersClient{},
	})
}
