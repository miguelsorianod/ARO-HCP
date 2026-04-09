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
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"

	"k8s.io/utils/clock"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/alertsmanagement/armalertsmanagement"

	"github.com/Azure/ARO-HCP/internal/utils"
	"github.com/Azure/ARO-HCP/test/cmd/aro-hcp-tests/internal/testutil"
	"github.com/Azure/ARO-HCP/test/util/timing"
)

//go:embed artifacts/*.html.tmpl
var templatesFS embed.FS

func mustReadArtifact(name string) []byte {
	ret, err := templatesFS.ReadFile("artifacts/" + name)
	if err != nil {
		panic(fmt.Sprintf("failed to read embedded template %q: %v", name, err))
	}
	return ret
}

func DefaultOptions() *RawOptions {
	return &RawOptions{}
}

func BindOptions(opts *RawOptions, cmd *cobra.Command) error {
	cmd.Flags().StringVar(&opts.TimingInputDir, "timing-input", opts.TimingInputDir, "Path to the directory holding timing outputs from an end-to-end test run.")
	cmd.Flags().StringVar(&opts.OutputDir, "output", opts.OutputDir, "Path to the directory where artifacts will be written.")
	cmd.Flags().StringVar(&opts.RenderedConfig, "rendered-config", opts.RenderedConfig, "Path to the rendered configuration YAML file.")
	cmd.Flags().StringVar(&opts.SubscriptionID, "subscription-id", opts.SubscriptionID, "Azure subscription ID.")
	cmd.Flags().StringVar(&opts.StartTimeFallback, "start-time-fallback", opts.StartTimeFallback, "Optional RFC3339 time to use as start time fallback when steps and test timing are unavailable.")
	cmd.Flags().StringVar(&opts.SeverityThreshold, "severity-threshold", opts.SeverityThreshold, "Include alerts at this severity level or more critical (Sev0=critical .. Sev4=verbose). E.g. Sev2 includes Sev0, Sev1, Sev2. If not set, all severities are shown.")
	return nil
}

type RawOptions struct {
	TimingInputDir    string
	OutputDir         string
	RenderedConfig    string
	SubscriptionID    string
	StartTimeFallback string
	SeverityThreshold string
}

type validatedOptions struct {
	*RawOptions
	severityThreshold int // -1 means no filter; 0=Sev0 .. 4=Sev4
}

type ValidatedOptions struct {
	*validatedOptions
}

type completedOptions struct {
	OutputDir         string
	Scope             string // Azure resource scope: /subscriptions/{sub}/resourceGroups/{rg}
	SvcWorkspace      string
	HcpWorkspace      string
	TimeWindow        timing.TimeWindow
	Queries           *QueriesConfig
	SeverityThreshold int // -1 means no filter; 0=Sev0 .. 4=Sev4
	SvcPromEndpoint   string
	HcpPromEndpoint   string
	cred              azcore.TokenCredential
}

type Options struct {
	*completedOptions
}

func (o *RawOptions) Validate() (*ValidatedOptions, error) {
	for _, item := range []struct {
		flag  string
		name  string
		value *string
	}{
		{flag: "output", name: "output dir", value: &o.OutputDir},
		{flag: "rendered-config", name: "rendered config", value: &o.RenderedConfig},
		{flag: "subscription-id", name: "subscription ID", value: &o.SubscriptionID},
	} {
		if item.value == nil || *item.value == "" {
			return nil, fmt.Errorf("the %s must be provided with --%s", item.name, item.flag)
		}
	}
	minSev, err := ParseSeverityThreshold(o.SeverityThreshold)
	if err != nil {
		return nil, err
	}
	return &ValidatedOptions{
		validatedOptions: &validatedOptions{RawOptions: o, severityThreshold: minSev},
	}, nil
}

func (o *ValidatedOptions) Complete(ctx context.Context) (*Options, error) {
	logger, err := logr.FromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("logger not found in context: %w", err)
	}

	// Create output directory early so we fail fast on bad paths before
	// making expensive Azure API calls.
	if err := os.MkdirAll(o.OutputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory %s: %w", o.OutputDir, err)
	}

	cfg, err := testutil.LoadRenderedConfig(o.RenderedConfig)
	if err != nil {
		return nil, err
	}

	regionRG, err := testutil.ConfigGetString(cfg, "regionRG")
	if err != nil {
		return nil, fmt.Errorf("failed to get regionRG from config: %w", err)
	}
	svcWorkspace, err := testutil.ConfigGetString(cfg, "monitoring.svcWorkspaceName")
	if err != nil {
		return nil, fmt.Errorf("failed to get monitoring.svcWorkspaceName from config: %w", err)
	}
	hcpWorkspace, err := testutil.ConfigGetString(cfg, "monitoring.hcpWorkspaceName")
	if err != nil {
		return nil, fmt.Errorf("failed to get monitoring.hcpWorkspaceName from config: %w", err)
	}

	steps, err := timing.LoadSteps(ctx, o.TimingInputDir)
	if err != nil {
		return nil, fmt.Errorf("failed to load steps: %w", err)
	}

	testTimingInfo, err := timing.LoadTestTimingInfo(ctx, o.TimingInputDir)
	if err != nil {
		return nil, fmt.Errorf("failed to load test timing info: %w", err)
	}

	var startFallback *time.Time
	if o.StartTimeFallback != "" {
		t, err := time.Parse(time.RFC3339, o.StartTimeFallback)
		if err != nil {
			return nil, fmt.Errorf("failed to parse --start-time-fallback %q: %w", o.StartTimeFallback, err)
		}
		startFallback = &t
	}

	tw, err := timing.ComputeTimeWindow(ctx, clock.RealClock{}, steps, testTimingInfo, startFallback)
	if err != nil {
		return nil, fmt.Errorf("failed to compute time window: %w", err)
	}

	cred, err := azidentity.NewDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{
		AdditionallyAllowedTenants: []string{"*"},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure credential: %w", err)
	}

	scope := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s", o.SubscriptionID, regionRG)

	completed := &completedOptions{
		OutputDir:         o.OutputDir,
		Scope:             scope,
		SvcWorkspace:      svcWorkspace,
		HcpWorkspace:      hcpWorkspace,
		TimeWindow:        tw,
		SeverityThreshold: o.severityThreshold,
		cred:              cred,
	}

	queries, err := loadQueriesConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load queries config: %w", err)
	}
	completed.Queries = queries
	logger.Info("loaded embedded queries config", "queries", len(queries.Queries))

	// Resolve Prometheus endpoints eagerly so we fail fast
	completed.SvcPromEndpoint, err = lookupPrometheusEndpoint(ctx, cred, o.SubscriptionID, regionRG, svcWorkspace)
	if err != nil {
		return nil, fmt.Errorf("failed to look up svc Prometheus endpoint for workspace %s in %s: %w", svcWorkspace, regionRG, err)
	}
	logger.Info("resolved svc Prometheus endpoint", "endpoint", completed.SvcPromEndpoint)

	completed.HcpPromEndpoint, err = lookupPrometheusEndpoint(ctx, cred, o.SubscriptionID, regionRG, hcpWorkspace)
	if err != nil {
		return nil, fmt.Errorf("failed to look up hcp Prometheus endpoint for workspace %s in %s: %w", hcpWorkspace, regionRG, err)
	}
	logger.Info("resolved hcp Prometheus endpoint", "endpoint", completed.HcpPromEndpoint)

	return &Options{completedOptions: completed}, nil
}

// templateData is the data passed to the HTML template.
type templateData struct {
	Alerts       []AlertSummary
	SvcWorkspace string
	HcpWorkspace string
	Scope        string
	TimeWindow   struct {
		Start string
		End   string
	}
	SeverityCounts map[armalertsmanagement.Severity]int
	HasAlerts      bool
}

func (o Options) Run(ctx context.Context) error {
	logger, err := logr.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("logger not found in context: %w", err)
	}

	allAlerts, err := fetchAlerts(ctx, o.cred, o.Scope, o.TimeWindow.Start, o.TimeWindow.End)
	if err != nil {
		return utils.TrackError(fmt.Errorf("failed to fetch alerts for scope %s, time window [%s to %s]: %w",
			o.Scope,
			o.TimeWindow.Start.Format(time.RFC3339), o.TimeWindow.End.Format(time.RFC3339), err))
	}

	alerts := filterAlertsBySeverity(allAlerts, o.SeverityThreshold)
	if o.SeverityThreshold >= 0 {
		logger.Info("filtered alerts by severity threshold", "threshold", fmt.Sprintf("Sev%d", o.SeverityThreshold), "before", len(allAlerts), "after", len(alerts))
	}
	jsonPath := filepath.Join(o.OutputDir, "alerts.json")
	jsonData, err := json.MarshalIndent(alerts, "", "  ")
	if err != nil {
		return utils.TrackError(fmt.Errorf("failed to marshal alerts to JSON: %w", err))
	}
	if err := os.WriteFile(jsonPath, jsonData, 0644); err != nil {
		return utils.TrackError(fmt.Errorf("failed to write %s: %w", jsonPath, err))
	}
	logger.Info("wrote alert JSON artifact", "path", jsonPath, "alerts", len(alerts))

	// Build template data
	severityCounts := map[armalertsmanagement.Severity]int{}
	for _, a := range alerts {
		severityCounts[a.Severity]++
	}

	data := templateData{
		Alerts:         alerts,
		SvcWorkspace:   o.SvcWorkspace,
		HcpWorkspace:   o.HcpWorkspace,
		Scope:          o.Scope,
		SeverityCounts: severityCounts,
		HasAlerts:      len(alerts) > 0,
	}
	data.TimeWindow.Start = o.TimeWindow.Start.UTC().Format(time.RFC3339)
	data.TimeWindow.End = o.TimeWindow.End.UTC().Format(time.RFC3339)

	// Render HTML artifact
	htmlPath := filepath.Join(o.OutputDir, "alerts-summary.html")
	if err := renderTemplate(htmlPath, data); err != nil {
		return utils.TrackError(fmt.Errorf("failed to render alerts HTML: %w", err))
	}
	logger.Info("wrote alert HTML artifact", "path", htmlPath)

	// Execute PromQL queries and render timeseries charts with alert overlays
	if o.Queries != nil {
		if err := o.runQueries(ctx); err != nil {
			return utils.TrackError(fmt.Errorf("PromQL query execution failed: %w", err))
		}
	}

	return nil
}

func (o Options) runQueries(ctx context.Context) error {
	logger, err := logr.FromContext(ctx)
	if err != nil {
		return fmt.Errorf("logger not found in context: %w", err)
	}
	httpClient := &http.Client{Timeout: 30 * time.Second}

	for _, q := range o.Queries.Queries {
		endpoint := resolveWorkspaceEndpoint(q, o.SvcPromEndpoint, o.HcpPromEndpoint)

		logger.Info("executing PromQL query", "title", q.Title, "workspace", q.Workspace)

		var results []PrometheusResult
		var queryErr string
		resp, err := queryRange(ctx, httpClient, o.cred, endpoint, q.Query, o.TimeWindow.Start, o.TimeWindow.End, q.Step)
		if err != nil {
			logger.Error(err, "PromQL query failed", "title", q.Title)
			queryErr = err.Error()
		} else {
			results = resp.Data.Result
		}

		// filename must match the Spyglass HTML lens regex .*-summary.*\.html
		// so that Prow renders it inline in the job UI.
		fileName := fmt.Sprintf("query-%s-summary.html", sanitizeTitle(q.Title))
		chartPath := filepath.Join(o.OutputDir, fileName)
		if err := renderTimeseriesChart(chartPath, q.Title, q.Query, queryErr, results, o.TimeWindow); err != nil {
			logger.Error(err, "failed to render timeseries chart", "title", q.Title)
			continue
		}
		logger.Info("wrote timeseries chart", "path", chartPath, "series", len(results))
	}
	return nil
}

// sanitizeTitle converts a title to a lowercase kebab-case string suitable for
// use in file names.
func sanitizeTitle(title string) string {
	title = strings.ToLower(title)
	title = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		return '-'
	}, title)
	// collapse multiple dashes
	for strings.Contains(title, "--") {
		title = strings.ReplaceAll(title, "--", "-")
	}
	return strings.Trim(title, "-")
}

func renderTemplate(outputPath string, data any) error {
	funcMap := template.FuncMap{
		"formatTime": func(t *time.Time) string {
			if t == nil {
				return "-"
			}
			return t.UTC().Format("2006-01-02 15:04:05")
		},
		"severityClass": severityCSSClass,
		"conditionClass": func(s string) string {
			switch s {
			case "Fired":
				return "condition-fired"
			case "Resolved":
				return "condition-resolved"
			default:
				return ""
			}
		},
		"truncate": func(s string, n int) string {
			if len(s) <= n {
				return s
			}
			return s[:n] + "..."
		},
	}

	tmplContent := mustReadArtifact("alerts.html.tmpl")
	tmpl, err := template.New("alerts").Funcs(funcMap).Parse(string(tmplContent))
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}
	if err := os.WriteFile(outputPath, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", outputPath, err)
	}
	return nil
}
