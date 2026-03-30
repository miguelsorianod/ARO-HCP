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
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-logr/logr"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armlocks"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"

	"github.com/Azure/ARO-HCP/tooling/cleanup-sweeper/pkg/engine/runner"
	armhelpers "github.com/Azure/ARO-HCP/tooling/cleanup-sweeper/pkg/engine/steps/arm"
)

// ResourceType is the ARM resource type for resource groups.
const ResourceType = "Microsoft.Resources/resourceGroups"

// DeleteStepConfig configures resource-group deletion.
type DeleteStepConfig struct {
	ResourceGroupName string
	RGClient          *armresources.ResourceGroupsClient
	LocksClient       *armlocks.ManagementLocksClient

	Name            string
	Retries         int
	ContinueOnError bool
	Verify          runner.VerifyFn
}

type deleteStep struct {
	cfg             DeleteStepConfig
	name            string
	retries         int
	continueOnError bool
	verify          runner.VerifyFn
}

var _ runner.Step = (*deleteStep)(nil)

// NewDeleteStep builds the resource-group deletion step.
func NewDeleteStep(cfg DeleteStepConfig) (runner.Step, error) {
	if strings.TrimSpace(cfg.ResourceGroupName) == "" {
		return nil, fmt.Errorf("resource group name is required")
	}
	if cfg.RGClient == nil {
		return nil, fmt.Errorf("resource groups client is required")
	}

	stepName := cfg.Name
	if strings.TrimSpace(stepName) == "" {
		stepName = "Delete resource group"
	}

	return &deleteStep{
		cfg:             cfg,
		name:            stepName,
		retries:         cfg.Retries,
		continueOnError: cfg.ContinueOnError,
		verify:          cfg.Verify,
	}, nil
}

// MustNewDeleteStep builds the step and panics on invalid config.
func MustNewDeleteStep(cfg DeleteStepConfig) runner.Step {
	step, err := NewDeleteStep(cfg)
	if err != nil {
		panic(err)
	}
	return step
}

func (s *deleteStep) Name() string {
	return s.name
}

func (s *deleteStep) RetryLimit() int {
	if s.retries < runner.DefaultRetries {
		return runner.DefaultRetries
	}
	return s.retries
}

func (s *deleteStep) ContinueOnError() bool {
	return s.continueOnError
}

func (s *deleteStep) Verify(ctx context.Context) error {
	if s.verify == nil {
		return nil
	}
	return s.verify(ctx)
}

func (s *deleteStep) Discover(ctx context.Context) ([]runner.Target, error) {
	logger, err := logr.FromContext(ctx)
	if err != nil {
		panic(err)
	}
	targets := []runner.Target{{Name: s.cfg.ResourceGroupName, Type: ResourceType}}
	if s.cfg.LocksClient == nil {
		return targets, nil
	}
	hasLocks, lockErr := armhelpers.HasResourceGroupLocks(ctx, s.cfg.LocksClient, s.cfg.ResourceGroupName)
	if lockErr != nil {
		logger.Info(
			"Failed to evaluate resource-group locks during discovery; keeping target",
			"step", s.Name(),
			"resource", s.cfg.ResourceGroupName,
			"error", lockErr,
		)
		return targets, nil
	}
	if !hasLocks {
		return targets, nil
	}

	logger.Info("Skipping deletion target", "step", s.Name(), "resource", s.cfg.ResourceGroupName, "reason", "locked")
	return nil, nil
}

func (s *deleteStep) Delete(ctx context.Context, target runner.Target, wait bool) error {
	poller, err := s.cfg.RGClient.BeginDelete(ctx, target.Name, nil)
	if err != nil {
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound {
			return nil
		}
		return err
	}
	if wait {
		_, err = poller.PollUntilDone(ctx, nil)
		return err
	}
	return nil
}
