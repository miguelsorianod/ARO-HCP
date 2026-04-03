// Copyright 2025 Microsoft Corporation
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

package gatherobservability

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	azcorearm "github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/alertsmanagement/armalertsmanagement"
)

// AlertSummary is a flattened representation of an Azure Monitor alert
// suitable for serialization and display.
type AlertSummary struct {
	Name           string                       `json:"name"`
	Severity       armalertsmanagement.Severity `json:"severity"`
	State          string                       `json:"state"`
	Condition      string                       `json:"condition"`
	FiredAt        *time.Time                   `json:"firedAt,omitempty"`
	ResolvedAt     *time.Time                   `json:"resolvedAt,omitempty"`
	Description    string                       `json:"description,omitempty"`
	AlertRule      string                       `json:"alertRule,omitempty"`
	TargetResource string                       `json:"targetResource,omitempty"`
	SignalType     string                       `json:"signalType,omitempty"`
	Workspace      string                       `json:"workspace,omitempty"`
}

func fetchAlerts(ctx context.Context, cred azcore.TokenCredential, scope string, start, end time.Time) ([]AlertSummary, error) {
	logger, err := logr.FromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("logger not found in context: %w", err)
	}

	client, err := armalertsmanagement.NewAlertsClient(scope, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create alerts client: %w", err)
	}

	var allAlerts []AlertSummary

	customTimeRange := fmt.Sprintf("%s/%s",
		start.UTC().Format(time.RFC3339),
		end.UTC().Format(time.RFC3339),
	)
	logger.Info("querying alerts fired within window", "scope", scope, "timeRange", customTimeRange)

	pager := client.NewGetAllPager(&armalertsmanagement.AlertsClientGetAllOptions{
		CustomTimeRange: &customTimeRange,
	})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list alerts: %w", err)
		}
		for _, alert := range page.Value {
			allAlerts = append(allAlerts, toAlertSummary(alert))
		}
	}
	logger.Info("alerts fetched", "count", len(allAlerts))
	return allAlerts, nil
}

func toAlertSummary(alert *armalertsmanagement.Alert) AlertSummary {
	s := AlertSummary{}
	if alert.Name != nil {
		s.Name = *alert.Name
	}
	if alert.Properties == nil || alert.Properties.Essentials == nil {
		return s
	}
	e := alert.Properties.Essentials
	if e.Severity != nil {
		s.Severity = *e.Severity
	}
	if e.AlertState != nil {
		s.State = string(*e.AlertState)
	}
	if e.MonitorCondition != nil {
		s.Condition = string(*e.MonitorCondition)
	}
	if e.StartDateTime != nil {
		s.FiredAt = e.StartDateTime
	}
	if e.MonitorConditionResolvedDateTime != nil {
		s.ResolvedAt = e.MonitorConditionResolvedDateTime
	}
	if e.Description != nil {
		s.Description = *e.Description
	}
	if e.AlertRule != nil {
		s.AlertRule = *e.AlertRule
	}
	if e.TargetResource != nil {
		s.TargetResource = *e.TargetResource
		if rid, err := azcorearm.ParseResourceID(s.TargetResource); err == nil {
			s.Workspace = rid.Name
		}
	}
	if e.SignalType != nil {
		s.SignalType = string(*e.SignalType)
	}
	return s
}
