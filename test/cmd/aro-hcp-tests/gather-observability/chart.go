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
	"cmp"
	"encoding/json"
	"fmt"
	"html/template"
	"math"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-echarts/go-echarts/v2/charts"
	"github.com/go-echarts/go-echarts/v2/opts"

	"k8s.io/utils/ptr"

	"github.com/Azure/ARO-HCP/test/util/timing"
)

const (
	// minLegendHeight is the minimum height for the chart legend area.
	minLegendHeight = 40
	// pixelsPerLegendEntry is the height per legend entry in timeseries charts.
	pixelsPerLegendEntry = 22
	// baseChartHeight is the base height for timeseries charts before legend.
	baseChartHeight = 400
	// legendBottomPadding is extra space below the legend area.
	legendBottomPadding = 20
)

// parsedSeries is a timeseries with parsed data points ready for charting.
type parsedSeries struct {
	label  string
	metric map[string]string
	data   []opts.LineData
}

func (s parsedSeries) peakValue() float64 {
	var peak float64
	for _, d := range s.data {
		if arr, ok := d.Value.([]any); ok && len(arr) == 2 {
			if v, ok := arr[1].(float64); ok && v > peak {
				peak = v
			}
		}
	}
	return peak
}

// queryPageData is the data passed to the query.html.tmpl template.
type queryPageData struct {
	Title      string
	Query      string
	HasData    bool
	Error      string
	ChartHTML  template.HTML // raw HTML from go-echarts, not escaped
	TimeWindow struct {
		Start string
		End   string
	}
}

func renderQueryPage(outputPath string, data queryPageData) error {
	tmplContent := mustReadArtifact("query.html.tmpl")
	tmpl, err := template.New("query").Parse(string(tmplContent))
	if err != nil {
		return fmt.Errorf("failed to parse query template: %w", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("failed to execute query template: %w", err)
	}
	if err := os.WriteFile(outputPath, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", outputPath, err)
	}
	return nil
}

// renderTimeseriesChart creates an interactive ECharts line chart from
// Prometheus query_range results. Each PrometheusResult becomes a separate
// series, labeled by its metric labels. Series where all values are zero
// are filtered out. If no data is available, a "no results" page is rendered.
func renderTimeseriesChart(outputPath, title, query, queryErr string, results []PrometheusResult, tw timing.TimeWindow) error {
	var series []parsedSeries
	for _, result := range results {
		if len(result.Values) == 0 {
			continue
		}

		var data []opts.LineData
		allZero := true
		for _, v := range result.Values {
			if len(v) < 2 {
				continue
			}
			ts, val, ok := parsePrometheusValue(v)
			if !ok || ts == 0 {
				continue
			}
			if val != 0 {
				allZero = false
			}
			data = append(data, opts.LineData{
				Value: []any{ts * 1000, val}, // ECharts time axis expects milliseconds
			})
		}

		if len(data) == 0 || allZero {
			continue
		}

		series = append(series, parsedSeries{
			metric: result.Metric,
			data:   data,
		})
	}

	if len(series) == 0 {
		data := queryPageData{Title: title, Query: query, Error: queryErr}
		data.TimeWindow.Start = tw.Start.UTC().Format(time.RFC3339)
		data.TimeWindow.End = tw.End.UTC().Format(time.RFC3339)
		return renderQueryPage(outputPath, data)
	}

	// Sort by peak value descending for consistent legend ordering
	slices.SortFunc(series, func(a, b parsedSeries) int {
		return cmp.Compare(b.peakValue(), a.peakValue())
	})
	subtitle := fmt.Sprintf("Window: %s — %s", tw.Start.UTC().Format(time.RFC3339), tw.End.UTC().Format(time.RFC3339))

	// Build labels: strip label keys that are the same across all series
	commonLabels := findCommonLabels(series)
	for i := range series {
		series[i].label = compactMetricLabel(series[i].metric, commonLabels)
	}

	// Adjust chart height for legend when many series
	legendHeight := max(minLegendHeight, len(series)*pixelsPerLegendEntry)
	chartHeight := baseChartHeight + legendHeight

	line := charts.NewLine()
	line.SetGlobalOptions(
		charts.WithInitializationOpts(opts.Initialization{
			PageTitle: title,
			Renderer:  "svg",
			Height:    fmt.Sprintf("%dpx", chartHeight),
			Width:     "1200px",
			Theme:     "dark",
		}),
		charts.WithTitleOpts(opts.Title{
			Title:      title,
			Subtitle:   subtitle,
			TitleStyle: &opts.TextStyle{Align: "left", Color: "#4E9AF1"},
			TextAlign:  "left",
			Left:       "center",
		}),
		charts.WithTooltipOpts(opts.Tooltip{
			Trigger: "axis",
		}),
		charts.WithLegendOpts(opts.Legend{
			Show:   ptr.To(true),
			Bottom: "0",
		}),
		charts.WithXAxisOpts(opts.XAxis{
			Type: "time",
			Min:  tw.Start.UnixMilli(),
			Max:  tw.End.UnixMilli(),
		}),
		charts.WithYAxisOpts(opts.YAxis{
			Type: "value",
		}),
		charts.WithGridOpts(opts.Grid{
			Bottom: fmt.Sprintf("%d", legendHeight+legendBottomPadding),
		}),
	)

	for _, s := range series {
		line.AddSeries(s.label, s.data,
			charts.WithLineChartOpts(opts.LineChart{
				ShowSymbol: ptr.To(false),
			}),
		)
	}

	// Extract just the chart div+script from go-echarts, stripping the outer HTML shell
	rendered := line.RenderContent()
	chartHTML := extractChartBody(rendered)

	data := queryPageData{
		Title:     title,
		Query:     query,
		HasData:   true,
		ChartHTML: template.HTML(chartHTML), //nolint:gosec // trusted go-echarts output
	}
	data.TimeWindow.Start = tw.Start.UTC().Format(time.RFC3339)
	data.TimeWindow.End = tw.End.UTC().Format(time.RFC3339)
	return renderQueryPage(outputPath, data)
}

// extractChartBody strips the outer HTML/head/body tags from go-echarts output
// and returns just the inner content (chart div, script, style).
func extractChartBody(rendered []byte) []byte {
	// Extract content between <body> and </body>
	start := bytes.Index(rendered, []byte("<body>"))
	end := bytes.Index(rendered, []byte("</body>"))
	if start >= 0 && end > start {
		return rendered[start+len("<body>") : end]
	}
	return rendered
}

// findCommonLabels returns label keys whose values are identical across all series.
func findCommonLabels(series []parsedSeries) map[string]bool {
	if len(series) <= 1 {
		return nil
	}
	common := make(map[string]bool)
	for k, v := range series[0].metric {
		same := true
		for _, s := range series[1:] {
			if s.metric[k] != v {
				same = false
				break
			}
		}
		if same {
			common[k] = true
		}
	}
	return common
}

// compactMetricLabel builds a short label showing only the label keys that
// differ across series. If only one differentiating key exists, shows just
// the value.
func compactMetricLabel(metric map[string]string, common map[string]bool) string {
	var keys []string
	for k := range metric {
		if !common[k] {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)

	if len(keys) == 0 {
		// all labels are common — fall back to full label
		return metricLabel(metric)
	}
	if len(keys) == 1 {
		return metric[keys[0]]
	}
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, metric[k]))
	}
	return strings.Join(parts, ", ")
}

// parsePrometheusValue extracts a unix timestamp and float value from a
// Prometheus [timestamp, "value"] pair. Returns ok=false for NaN values
// which cannot be serialized to JSON. Inf values are capped to a large
// finite number so they can be displayed on charts.
func parsePrometheusValue(v []any) (ts int64, val float64, ok bool) {
	switch t := v[0].(type) {
	case float64:
		ts = int64(t)
	case json.Number:
		if n, err := t.Int64(); err == nil {
			ts = n
		}
	}

	switch s := v[1].(type) {
	case string:
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			val = f
		}
	case float64:
		val = s
	}

	if math.IsNaN(val) {
		return ts, 0, false
	}
	if math.IsInf(val, 1) {
		val = math.MaxFloat64
	} else if math.IsInf(val, -1) {
		val = -math.MaxFloat64
	}
	return ts, val, true
}

// metricLabel builds a display label from Prometheus metric labels.
func metricLabel(metric map[string]string) string {
	if len(metric) == 0 {
		return "value"
	}
	keys := make([]string, 0, len(metric))
	for k := range metric {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, metric[k]))
	}
	return strings.Join(parts, ", ")
}
