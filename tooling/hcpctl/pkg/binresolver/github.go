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

package binresolver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

// GitHubSource downloads binaries from GitHub releases.
type GitHubSource struct {
	Owner string // GitHub organization, e.g. "openshift"
	Repo  string // GitHub repository, e.g. "must-gather-clean"

	APIBaseURL      string
	DownloadBaseURL string
}

type githubReleaseResponse struct {
	TagName string `json:"tag_name"`
}

func (s *GitHubSource) apiBase() string {
	if s.APIBaseURL != "" {
		return s.APIBaseURL
	}
	return "https://api.github.com"
}

func (s *GitHubSource) downloadBase() string {
	if s.DownloadBaseURL != "" {
		return s.DownloadBaseURL
	}
	return "https://github.com"
}

func (s *GitHubSource) LatestTagName(ctx context.Context, client *http.Client) (string, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/releases/latest", s.apiBase(), s.Owner, s.Repo)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to query GitHub API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var release githubReleaseResponse
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", fmt.Errorf("failed to decode GitHub API response: %w", err)
	}

	if release.TagName == "" {
		return "", fmt.Errorf("GitHub API returned empty tag name")
	}

	return release.TagName, nil
}

func (s *GitHubSource) DownloadURL(version, asset string) string {
	return fmt.Sprintf("%s/%s/%s/releases/download/%s/%s",
		s.downloadBase(), s.Owner, s.Repo, version, asset)
}

func (s *GitHubSource) ReleasesURL() string {
	return fmt.Sprintf("%s/%s/%s/releases", s.downloadBase(), s.Owner, s.Repo)
}
