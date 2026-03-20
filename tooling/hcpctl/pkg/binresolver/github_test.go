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
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGitHubTokenAuth(t *testing.T) {
	var receivedAuth string
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"tag_name": "v1.0.0"}`)
	}))
	defer apiServer.Close()

	source := &GitHubSource{
		Owner:      "test",
		Repo:       "test",
		APIBaseURL: apiServer.URL,
	}

	t.Run("with GITHUB_TOKEN set", func(t *testing.T) {
		t.Setenv("GITHUB_TOKEN", "test-token-123")
		receivedAuth = ""

		version, err := source.LatestVersion(context.Background(), http.DefaultClient)
		require.NoError(t, err)
		assert.Equal(t, "v1.0.0", version)
		assert.Equal(t, "Bearer test-token-123", receivedAuth)
	})

	t.Run("without GITHUB_TOKEN", func(t *testing.T) {
		t.Setenv("GITHUB_TOKEN", "")
		receivedAuth = ""

		version, err := source.LatestVersion(context.Background(), http.DefaultClient)
		require.NoError(t, err)
		assert.Equal(t, "v1.0.0", version)
		assert.Empty(t, receivedAuth)
	})
}

func TestGitHubSourceDownloadURL(t *testing.T) {
	source := &GitHubSource{Owner: "openshift", Repo: "must-gather-clean"}

	url := source.DownloadURL("v1.2.3", "must-gather-clean-linux-amd64.tar.gz")
	assert.Equal(t, "https://github.com/openshift/must-gather-clean/releases/download/v1.2.3/must-gather-clean-linux-amd64.tar.gz", url)
}

func TestGitHubSourceDownloadURLWithOverride(t *testing.T) {
	source := &GitHubSource{
		Owner:           "openshift",
		Repo:            "must-gather-clean",
		DownloadBaseURL: "https://custom.example.com",
	}

	url := source.DownloadURL("v1.0.0", "asset.tar.gz")
	assert.Equal(t, "https://custom.example.com/openshift/must-gather-clean/releases/download/v1.0.0/asset.tar.gz", url)
}

func TestGitHubSourceReleasesURL(t *testing.T) {
	source := &GitHubSource{Owner: "openshift", Repo: "must-gather-clean"}
	assert.Equal(t, "https://github.com/openshift/must-gather-clean/releases", source.ReleasesURL())
}

func TestGitHubSourceReleasesURLWithOverride(t *testing.T) {
	source := &GitHubSource{
		Owner:           "openshift",
		Repo:            "must-gather-clean",
		DownloadBaseURL: "https://custom.example.com",
	}
	assert.Equal(t, "https://custom.example.com/openshift/must-gather-clean/releases", source.ReleasesURL())
}
