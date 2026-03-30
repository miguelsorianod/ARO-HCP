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
	"context"
	"fmt"
	"strings"

	"github.com/go-logr/logr"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v8"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armlocks"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"

	"github.com/Azure/ARO-HCP/tooling/cleanup-sweeper/pkg/engine/runner"
	armhelpers "github.com/Azure/ARO-HCP/tooling/cleanup-sweeper/pkg/engine/steps/arm"
	"github.com/Azure/ARO-HCP/tooling/cleanup-sweeper/pkg/engine/steps/common"
)

// NSPResourceType is the ARM resource type for network security perimeters.
const NSPResourceType = "Microsoft.Network/networkSecurityPerimeters"

// NSPForceDeleteStepConfig configures force deletion of NSP resources.
type NSPForceDeleteStepConfig struct {
	ResourceGroupName string
	ResourcesClient   *armresources.Client
	LocksClient       *armlocks.ManagementLocksClient
	NSPClient         *armnetwork.SecurityPerimetersClient

	Name            string
	Retries         int
	ContinueOnError bool
	Verify          runner.VerifyFn
}

type nspForceDeleteStep struct {
	cfg             NSPForceDeleteStepConfig
	name            string
	retries         int
	continueOnError bool
	verify          runner.VerifyFn
}

var _ runner.Step = (*nspForceDeleteStep)(nil)

// NewNSPForceDeleteStep builds the NSP force-delete step.
func NewNSPForceDeleteStep(cfg NSPForceDeleteStepConfig) (runner.Step, error) {
	if strings.TrimSpace(cfg.ResourceGroupName) == "" {
		return nil, fmt.Errorf("resource group name is required")
	}
	if cfg.ResourcesClient == nil {
		return nil, fmt.Errorf("resources client is required")
	}
	if cfg.LocksClient == nil {
		return nil, fmt.Errorf("management locks client is required")
	}
	if cfg.NSPClient == nil {
		return nil, fmt.Errorf("network security perimeters client is required")
	}

	stepName := cfg.Name
	if strings.TrimSpace(stepName) == "" {
		stepName = "Delete network security perimeters"
	}

	return &nspForceDeleteStep{
		cfg:             cfg,
		name:            stepName,
		retries:         cfg.Retries,
		continueOnError: cfg.ContinueOnError,
		verify:          cfg.Verify,
	}, nil
}

// MustNewNSPForceDeleteStep builds the step and panics on invalid config.
func MustNewNSPForceDeleteStep(cfg NSPForceDeleteStepConfig) runner.Step {
	step, err := NewNSPForceDeleteStep(cfg)
	if err != nil {
		panic(err)
	}
	return step
}

func (s *nspForceDeleteStep) Name() string {
	return s.name
}

func (s *nspForceDeleteStep) RetryLimit() int {
	if s.retries < runner.DefaultRetries {
		return runner.DefaultRetries
	}
	return s.retries
}

func (s *nspForceDeleteStep) ContinueOnError() bool {
	return s.continueOnError
}

func (s *nspForceDeleteStep) Verify(ctx context.Context) error {
	if s.verify == nil {
		return nil
	}
	return s.verify(ctx)
}

func (s *nspForceDeleteStep) Discover(ctx context.Context) ([]runner.Target, error) {
	logger, err := logr.FromContext(ctx)
	if err != nil {
		panic(err)
	}
	skipReporter := common.NewDiscoverySkipReporter(s.Name())
	defer skipReporter.Flush(logger)

	resources, err := armhelpers.ListByType(ctx, s.cfg.ResourcesClient, s.cfg.ResourceGroupName, NSPResourceType)
	if err != nil {
		return nil, err
	}
	targets := make([]runner.Target, 0, len(resources))
	for i, resource := range resources {
		if resource == nil || resource.ID == nil || resource.Name == nil || resource.Type == nil {
			skipReporter.Record(
				logger,
				"invalid_resource_payload",
				"index", i,
				"resourceType", NSPResourceType,
			)
			continue
		}
		targets = append(targets, runner.Target{
			ID:   *resource.ID,
			Name: *resource.Name,
			Type: *resource.Type,
		})
	}
	return armhelpers.FilterUnlockedTargets(ctx, s.cfg.LocksClient, s.Name(), targets), nil
}

func (s *nspForceDeleteStep) Delete(ctx context.Context, target runner.Target, wait bool) error {
	poller, err := s.cfg.NSPClient.BeginDelete(ctx, s.cfg.ResourceGroupName, target.Name, &armnetwork.SecurityPerimetersClientBeginDeleteOptions{
		ForceDeletion: to.Ptr(true),
	})
	if err != nil {
		return err
	}
	if wait {
		_, err = poller.PollUntilDone(ctx, nil)
		return err
	}
	return nil
}
