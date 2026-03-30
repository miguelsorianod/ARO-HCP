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
	"context"
	"fmt"
	"strings"

	"github.com/go-logr/logr"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armlocks"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"

	"github.com/Azure/ARO-HCP/tooling/cleanup-sweeper/pkg/engine/runner"
	"github.com/Azure/ARO-HCP/tooling/cleanup-sweeper/pkg/engine/steps/common"
)

// ResourceSelector defines inclusion or exclusion resource-type filters.
type ResourceSelector struct {
	IncludedResourceTypes []string
	ExcludedResourceTypes []string
}

// DeletionStepConfig configures the generic ARM deletion step.
type DeletionStepConfig struct {
	ResourceGroupName string
	Client            *armresources.Client
	LocksClient       *armlocks.ManagementLocksClient
	APIVersionCache   *APIVersionCache
	Selector          ResourceSelector

	Name            string
	Retries         int
	ContinueOnError bool
	Verify          runner.VerifyFn
}

type deletionStep struct {
	cfg             DeletionStepConfig
	name            string
	retries         int
	continueOnError bool
	verify          runner.VerifyFn
	apiVersionCache *APIVersionCache
	hasIncluded     bool
}

var _ runner.Step = (*deletionStep)(nil)

// NewDeletionStep builds a generic ARM resource deletion step.
func NewDeletionStep(cfg DeletionStepConfig) (runner.Step, error) {
	selector := cfg.Selector
	hasIncluded := len(selector.IncludedResourceTypes) > 0
	hasExcluded := len(selector.ExcludedResourceTypes) > 0
	if hasIncluded == hasExcluded {
		return nil, fmt.Errorf("exactly one of IncludedResourceTypes or ExcludedResourceTypes must be set")
	}
	if strings.TrimSpace(cfg.ResourceGroupName) == "" {
		return nil, fmt.Errorf("resource group name is required")
	}
	if cfg.Client == nil {
		return nil, fmt.Errorf("resources client is required")
	}
	if cfg.LocksClient == nil {
		return nil, fmt.Errorf("management locks client is required")
	}
	if cfg.APIVersionCache == nil {
		return nil, fmt.Errorf("api version cache is required")
	}

	stepName := cfg.Name
	if stepName == "" {
		switch {
		case hasIncluded && len(selector.IncludedResourceTypes) == 1:
			stepName = fmt.Sprintf("Delete %s", selector.IncludedResourceTypes[0])
		case hasIncluded:
			stepName = "Delete selected resources"
		default:
			stepName = "Delete resources excluding selected types"
		}
	}

	return &deletionStep{
		cfg:             cfg,
		name:            stepName,
		retries:         cfg.Retries,
		continueOnError: cfg.ContinueOnError,
		verify:          cfg.Verify,
		apiVersionCache: cfg.APIVersionCache,
		hasIncluded:     hasIncluded,
	}, nil
}

// MustNewDeletionStep builds a deletion step and panics on invalid config.
func MustNewDeletionStep(cfg DeletionStepConfig) runner.Step {
	step, err := NewDeletionStep(cfg)
	if err != nil {
		panic(err)
	}
	return step
}

func (s *deletionStep) Name() string {
	return s.name
}

func (s *deletionStep) RetryLimit() int {
	if s.retries < runner.DefaultRetries {
		return runner.DefaultRetries
	}
	return s.retries
}

func (s *deletionStep) ContinueOnError() bool {
	return s.continueOnError
}

func (s *deletionStep) Verify(ctx context.Context) error {
	if s.verify == nil {
		return nil
	}
	return s.verify(ctx)
}

func (s *deletionStep) Discover(ctx context.Context) ([]runner.Target, error) {
	logger, err := logr.FromContext(ctx)
	if err != nil {
		panic(err)
	}
	skipReporter := common.NewDiscoverySkipReporter(s.Name())
	defer skipReporter.Flush(logger)

	targets := []runner.Target{}
	seenByID := sets.New[string]()

	appendTarget := func(resource *armresources.GenericResourceExpanded, source string, index int) {
		if resource == nil || resource.ID == nil || resource.Name == nil || resource.Type == nil {
			skipReporter.Record(
				logger,
				"invalid_resource_payload",
				"source", source,
				"index", index,
			)
			return
		}
		id := *resource.ID
		if seenByID.Has(id) {
			return
		}
		seenByID.Insert(id)
		target := runner.Target{
			ID:   id,
			Name: *resource.Name,
			Type: *resource.Type,
		}

		targets = append(targets, target)
	}

	selector := s.cfg.Selector
	if s.hasIncluded {
		for _, resourceType := range selector.IncludedResourceTypes {
			resources, err := ListByType(ctx, s.cfg.Client, s.cfg.ResourceGroupName, resourceType)
			if err != nil {
				return nil, err
			}
			for i, resource := range resources {
				appendTarget(resource, "listByType", i)
			}
		}
		return FilterUnlockedTargets(ctx, s.cfg.LocksClient, s.Name(), targets), nil
	}

	excluded := sets.New[string]()
	for _, t := range selector.ExcludedResourceTypes {
		excluded.Insert(strings.ToLower(t))
	}

	pager := s.cfg.Client.NewListByResourceGroupPager(s.cfg.ResourceGroupName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list resources: %w", err)
		}
		for i, resource := range page.Value {
			if resource == nil || resource.Type == nil {
				skipReporter.Record(
					logger,
					"missing_resource_type",
					"source", "listByResourceGroup",
					"index", i,
				)
				continue
			}
			if excluded.Has(strings.ToLower(*resource.Type)) {
				continue
			}
			appendTarget(resource, "listByResourceGroup", i)
		}
	}
	return FilterUnlockedTargets(ctx, s.cfg.LocksClient, s.Name(), targets), nil
}

func (s *deletionStep) Delete(ctx context.Context, target runner.Target, wait bool) error {
	apiVersion, err := s.apiVersionCache.Get(ctx, target.Type)
	if err != nil {
		return fmt.Errorf("failed to resolve API version for %s: %w", target.Type, err)
	}
	return DeleteByID(ctx, s.cfg.Client, target.ID, apiVersion, wait)
}
