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

package dns

import (
	"context"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armlocks"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
)

func TestNewDeleteNSDelegationRecordsStep_ExecutionOptions(t *testing.T) {
	t.Parallel()

	defaultCfg := validDeleteNSDelegationRecordsStepConfig()
	defaultStep, err := NewDeleteNSDelegationRecordsStep(defaultCfg)
	if err != nil {
		t.Fatalf("expected constructor to succeed, got error: %v", err)
	}
	if got := defaultStep.Name(); got != "Delete parent NS delegations" {
		t.Fatalf("expected default step name %q, got %q", "Delete parent NS delegations", got)
	}
	if got := defaultStep.RetryLimit(); got != 1 {
		t.Fatalf("expected default retry limit 1, got %d", got)
	}
	if got := defaultStep.ContinueOnError(); got {
		t.Fatalf("expected continueOnError false, got %t", got)
	}

	customCfg := validDeleteNSDelegationRecordsStepConfig()
	customCfg.Name = "custom-name"
	customCfg.Retries = 4
	customCfg.ContinueOnError = true
	customStep, err := NewDeleteNSDelegationRecordsStep(customCfg)
	if err != nil {
		t.Fatalf("expected constructor to succeed, got error: %v", err)
	}
	if got := customStep.Name(); got != "custom-name" {
		t.Fatalf("expected step name %q, got %q", "custom-name", got)
	}
	if got := customStep.RetryLimit(); got != 4 {
		t.Fatalf("expected retry limit 4, got %d", got)
	}
	if got := customStep.ContinueOnError(); !got {
		t.Fatalf("expected continueOnError true, got %t", got)
	}
}

func TestNewDeleteNSDelegationRecordsStep_ReturnsErrorWhenInvalid(t *testing.T) {
	t.Parallel()

	cfg := validDeleteNSDelegationRecordsStepConfig()
	cfg.Credential = nil
	if _, err := NewDeleteNSDelegationRecordsStep(cfg); err == nil {
		t.Fatalf("expected validation error when credential is missing")
	}
}

func TestMustNewDeleteNSDelegationRecordsStep_PanicsWhenInvalid(t *testing.T) {
	t.Parallel()

	cfg := validDeleteNSDelegationRecordsStepConfig()
	cfg.SubsClient = nil

	defer func() {
		if recover() == nil {
			t.Fatalf("expected panic for invalid config")
		}
	}()
	_ = MustNewDeleteNSDelegationRecordsStep(cfg)
}

func TestParseNSRecordSetTargetID(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name              string
		id                string
		expectErr         bool
		wantSubscription  string
		wantResourceGroup string
		wantZoneName      string
		wantRecordSetName string
	}{
		{
			name:              "valid NS record set ID",
			id:                "/subscriptions/1d3378d3-5a3f-4712-85a1-2485495dfc4b/resourceGroups/global/providers/Microsoft.Network/dnszones/hcp.osadev.cloud/NS/usw3rvaz",
			expectErr:         false,
			wantSubscription:  "1d3378d3-5a3f-4712-85a1-2485495dfc4b",
			wantResourceGroup: "global",
			wantZoneName:      "hcp.osadev.cloud",
			wantRecordSetName: "usw3rvaz",
		},
		{
			name:      "invalid ID",
			id:        "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Network/dnszones",
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			subscriptionID, resourceGroup, zoneName, recordSetName, err := parseNSRecordSetTargetID(tc.id)
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected parse error")
				}
				return
			}
			if err != nil {
				t.Fatalf("expected parse to succeed, got error: %v", err)
			}
			if subscriptionID != tc.wantSubscription {
				t.Fatalf("unexpected subscriptionID: %q", subscriptionID)
			}
			if resourceGroup != tc.wantResourceGroup {
				t.Fatalf("unexpected resourceGroup: %q", resourceGroup)
			}
			if zoneName != tc.wantZoneName {
				t.Fatalf("unexpected zoneName: %q", zoneName)
			}
			if recordSetName != tc.wantRecordSetName {
				t.Fatalf("unexpected recordSetName: %q", recordSetName)
			}
		})
	}
}

func validDeleteNSDelegationRecordsStepConfig() DeleteNSDelegationRecordsStepConfig {
	return DeleteNSDelegationRecordsStepConfig{
		ResourceGroupName: "rg",
		Credential:        testCredential{},
		LocksClient:       &armlocks.ManagementLocksClient{},
		ResourcesClient:   &armresources.Client{},
		SubsClient:        &armsubscriptions.Client{},
	}
}

type testCredential struct{}

func (testCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "token", ExpiresOn: time.Now().Add(time.Hour)}, nil
}
