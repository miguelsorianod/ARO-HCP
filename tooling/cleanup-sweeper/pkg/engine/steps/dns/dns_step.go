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
	"errors"
	"fmt"
	"strings"

	"github.com/go-logr/logr"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	azcorearm "github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armlocks"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"

	"github.com/Azure/ARO-HCP/tooling/cleanup-sweeper/pkg/engine/runner"
	armhelpers "github.com/Azure/ARO-HCP/tooling/cleanup-sweeper/pkg/engine/steps/arm"
	"github.com/Azure/ARO-HCP/tooling/cleanup-sweeper/pkg/engine/steps/common"
)

// DNSZonesResourceType is the ARM resource type for DNS zones.
const DNSZonesResourceType = "Microsoft.Network/dnszones"

// NSRecordSetResourceType is the ARM resource type for NS record sets.
const NSRecordSetResourceType = "Microsoft.Network/dnszones/NS"

// DeleteNSDelegationRecordsStepConfig configures NS delegation cleanup.
type DeleteNSDelegationRecordsStepConfig struct {
	ResourceGroupName string
	Credential        azcore.TokenCredential
	LocksClient       *armlocks.ManagementLocksClient
	ResourcesClient   *armresources.Client
	SubsClient        *armsubscriptions.Client

	Name            string
	Retries         int
	ContinueOnError bool
	Verify          runner.VerifyFn
}

type deleteNSDelegationRecordsStep struct {
	cfg             DeleteNSDelegationRecordsStepConfig
	name            string
	retries         int
	continueOnError bool
	verify          runner.VerifyFn
}

var _ runner.Step = (*deleteNSDelegationRecordsStep)(nil)

// NewDeleteNSDelegationRecordsStep builds the NS delegation cleanup step.
func NewDeleteNSDelegationRecordsStep(cfg DeleteNSDelegationRecordsStepConfig) (runner.Step, error) {
	if strings.TrimSpace(cfg.ResourceGroupName) == "" {
		return nil, fmt.Errorf("resource group name is required")
	}
	if cfg.Credential == nil {
		return nil, fmt.Errorf("azure credential is required")
	}
	if cfg.LocksClient == nil {
		return nil, fmt.Errorf("management locks client is required")
	}
	if cfg.ResourcesClient == nil {
		return nil, fmt.Errorf("resources client is required")
	}
	if cfg.SubsClient == nil {
		return nil, fmt.Errorf("subscriptions client is required")
	}

	stepName := cfg.Name
	if strings.TrimSpace(stepName) == "" {
		stepName = "Delete parent NS delegations"
	}

	return &deleteNSDelegationRecordsStep{
		cfg:             cfg,
		name:            stepName,
		retries:         cfg.Retries,
		continueOnError: cfg.ContinueOnError,
		verify:          cfg.Verify,
	}, nil
}

// MustNewDeleteNSDelegationRecordsStep builds the step and panics on invalid config.
func MustNewDeleteNSDelegationRecordsStep(cfg DeleteNSDelegationRecordsStepConfig) runner.Step {
	step, err := NewDeleteNSDelegationRecordsStep(cfg)
	if err != nil {
		panic(err)
	}
	return step
}

func (s *deleteNSDelegationRecordsStep) Name() string {
	return s.name
}

func (s *deleteNSDelegationRecordsStep) RetryLimit() int {
	if s.retries < runner.DefaultRetries {
		return runner.DefaultRetries
	}
	return s.retries
}

func (s *deleteNSDelegationRecordsStep) ContinueOnError() bool {
	return s.continueOnError
}

func (s *deleteNSDelegationRecordsStep) Verify(ctx context.Context) error {
	if s.verify == nil {
		return nil
	}
	return s.verify(ctx)
}

func (s *deleteNSDelegationRecordsStep) Discover(ctx context.Context) ([]runner.Target, error) {
	logger, err := logr.FromContext(ctx)
	if err != nil {
		panic(err)
	}
	skipReporter := common.NewDiscoverySkipReporter(s.Name())
	defer skipReporter.Flush(logger)

	childZones, err := armhelpers.ListByType(ctx, s.cfg.ResourcesClient, s.cfg.ResourceGroupName, DNSZonesResourceType)
	if err != nil {
		return nil, err
	}
	targets := make([]runner.Target, 0, len(childZones))
	for i, resource := range childZones {
		if resource == nil || resource.Name == nil {
			skipReporter.Record(
				logger,
				"invalid_dns_zone_payload",
				"index", i,
			)
			continue
		}
		childZone := *resource.Name
		parentZone, recordSetName, ok := parseDelegation(childZone)
		if !ok {
			skipReporter.Record(
				logger,
				"not_a_delegated_child_zone",
				"zone", childZone,
			)
			continue
		}

		delegationTargets, err := discoverNSDelegationRecordTargets(
			ctx,
			s.cfg.Credential,
			s.cfg.SubsClient,
			parentZone,
			recordSetName,
			logger,
			skipReporter,
		)
		if err != nil {
			logger.Info(
				fmt.Sprintf("[WARNING] Failed NS delegation discovery for child zone %q; continuing", childZone),
				"parentZone", parentZone,
				"recordSetName", recordSetName,
				"error", err,
			)
		}
		targets = append(targets, delegationTargets...)
	}
	return armhelpers.FilterUnlockedTargets(ctx, s.cfg.LocksClient, s.Name(), targets), nil
}

func (s *deleteNSDelegationRecordsStep) Delete(ctx context.Context, target runner.Target, _ bool) error {
	subscriptionID, resourceGroup, zoneName, recordSetName, err := parseNSRecordSetTargetID(target.ID)
	if err != nil {
		return err
	}
	return deleteNSRecordSet(ctx, s.cfg.Credential, subscriptionID, resourceGroup, zoneName, recordSetName)
}

func discoverNSDelegationRecordTargets(
	ctx context.Context,
	credential azcore.TokenCredential,
	subsClient *armsubscriptions.Client,
	parentZone, recordSetName string,
	logger logr.Logger,
	skipReporter *common.DiscoverySkipReporter,
) ([]runner.Target, error) {
	targets := []runner.Target{}
	var errs []error
	subsPager := subsClient.NewListPager(nil)
	for subsPager.More() {
		page, err := subsPager.NextPage(ctx)
		if err != nil {
			wrappedErr := fmt.Errorf("failed listing subscriptions while cleaning NS records for parent zone %q: %w", parentZone, err)
			errs = append(errs, wrappedErr)
			continue
		}

		for _, sub := range page.Value {
			if sub.SubscriptionID == nil {
				skipReporter.Record(
					logger,
					"missing_subscription_id",
					"parentZone", parentZone,
					"recordSetName", recordSetName,
				)
				continue
			}

			subID := *sub.SubscriptionID
			dnsClient, err := armdns.NewZonesClient(subID, credential, nil)
			if err != nil {
				wrappedErr := fmt.Errorf("failed creating DNS zones client for subscription %q: %w", subID, err)
				errs = append(errs, wrappedErr)
				continue
			}
			recordSetsClient, err := armdns.NewRecordSetsClient(subID, credential, nil)
			if err != nil {
				wrappedErr := fmt.Errorf("failed creating DNS record-sets client for subscription %q: %w", subID, err)
				errs = append(errs, wrappedErr)
				continue
			}

			zonesPager := dnsClient.NewListPager(nil)
			for zonesPager.More() {
				zonePage, err := zonesPager.NextPage(ctx)
				if err != nil {
					wrappedErr := fmt.Errorf("failed listing zones in subscription %q while looking for parent zone %q: %w", subID, parentZone, err)
					errs = append(errs, wrappedErr)
					continue
				}

				for _, zone := range zonePage.Value {
					if zone == nil || zone.Name == nil || zone.ID == nil {
						skipReporter.Record(
							logger,
							"invalid_dns_zone_payload",
							"subscriptionID", subID,
							"parentZone", parentZone,
						)
						continue
					}
					if !strings.EqualFold(*zone.Name, parentZone) {
						continue
					}

					parsedID, err := azcorearm.ParseResourceID(*zone.ID)
					if err != nil {
						wrappedErr := fmt.Errorf("failed parsing zone ID %q: %w", *zone.ID, err)
						errs = append(errs, wrappedErr)
						continue
					}
					if parsedID.ResourceGroupName == "" {
						wrappedErr := fmt.Errorf("zone ID %q does not include a resource group", *zone.ID)
						errs = append(errs, wrappedErr)
						continue
					}

					recordSetID := buildNSRecordSetID(subID, parsedID.ResourceGroupName, parentZone, recordSetName)
					if _, err := recordSetsClient.Get(ctx, parsedID.ResourceGroupName, parentZone, recordSetName, armdns.RecordTypeNS, nil); err != nil {
						wrappedErr := fmt.Errorf("failed getting NS record-set %q in zone %q (%s/%s): %w", recordSetName, parentZone, subID, parsedID.ResourceGroupName, err)
						errs = append(errs, wrappedErr)
						continue
					}
					targets = append(targets, runner.Target{
						ID:   recordSetID,
						Name: parentZone + "/" + recordSetName,
						Type: NSRecordSetResourceType,
					})
				}
			}
		}
	}

	return targets, errors.Join(errs...)
}

func deleteNSRecordSet(ctx context.Context, credential azcore.TokenCredential, subscriptionID, resourceGroup, zoneName, recordSetName string) error {
	recordSetsClient, err := armdns.NewRecordSetsClient(subscriptionID, credential, nil)
	if err != nil {
		return err
	}

	_, err = recordSetsClient.Delete(ctx, resourceGroup, zoneName, recordSetName, armdns.RecordTypeNS, nil)
	return err
}

func parseDelegation(childZone string) (parentZone string, recordSetName string, ok bool) {
	parts := strings.Split(childZone, ".")
	if len(parts) <= 2 {
		return "", "", false
	}
	return strings.Join(parts[1:], "."), parts[0], true
}

func buildNSRecordSetID(subscriptionID, resourceGroup, zoneName, recordSetName string) string {
	return "/subscriptions/" + subscriptionID +
		"/resourceGroups/" + resourceGroup +
		"/providers/Microsoft.Network/dnszones/" + zoneName +
		"/NS/" + recordSetName
}

func parseNSRecordSetTargetID(id string) (subscriptionID, resourceGroup, zoneName, recordSetName string, err error) {
	parsed, err := azcorearm.ParseResourceID(id)
	if err != nil {
		return "", "", "", "", err
	}
	if parsed.SubscriptionID == "" || parsed.ResourceGroupName == "" {
		return "", "", "", "", fmt.Errorf("invalid NS record-set target ID: %s", id)
	}

	// For an ID shaped as:
	// /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Network/dnszones/<zone>/NS/<recordSet>
	// ParseResourceID sets parsed.Name to the leaf resource name (<recordSet>), so we need to read <zone>
	// from the parent segment.
	recordSetName = strings.TrimSpace(parsed.Name)
	if recordSetName == "" {
		recordSetName = strings.TrimSpace(extractResourceIDSegmentValue(id, "NS"))
	}
	if recordSetName == "" {
		return "", "", "", "", fmt.Errorf("invalid NS record-set target name in ID: %s", id)
	}

	if parsed.Parent != nil {
		zoneName = strings.TrimSpace(parsed.Parent.Name)
	}
	if zoneName == "" {
		zoneName = strings.TrimSpace(extractResourceIDSegmentValue(id, "dnszones"))
	}
	if zoneName == "" {
		return "", "", "", "", fmt.Errorf("invalid NS record-set target name in ID: %s", id)
	}

	return parsed.SubscriptionID, parsed.ResourceGroupName, zoneName, recordSetName, nil
}

func extractResourceIDSegmentValue(resourceID, key string) string {
	parts := strings.Split(strings.Trim(resourceID, "/"), "/")
	for i := 0; i+1 < len(parts); i++ {
		if strings.EqualFold(parts[i], key) {
			return parts[i+1]
		}
	}
	return ""
}
