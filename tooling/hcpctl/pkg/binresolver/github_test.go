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
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGitHubSourceDownloadURL(t *testing.T) {
	source := &GitHubSource{Owner: "openshift", Repo: "must-gather-clean"}

	url := source.downloadURL("v1.2.3", "must-gather-clean-linux-amd64.tar.gz")
	assert.Equal(t, "https://github.com/openshift/must-gather-clean/releases/download/v1.2.3/must-gather-clean-linux-amd64.tar.gz", url)
}

func TestGitHubSourceDownloadURLWithOverride(t *testing.T) {
	source := &GitHubSource{
		Owner:           "openshift",
		Repo:            "must-gather-clean",
		DownloadBaseURL: "https://custom.example.com",
	}

	url := source.downloadURL("v1.0.0", "asset.tar.gz")
	assert.Equal(t, "https://custom.example.com/openshift/must-gather-clean/releases/download/v1.0.0/asset.tar.gz", url)
}

func TestGitHubDownloadRetriesOnFailure(t *testing.T) {
	binaryContent := []byte("test binary content")

	// Server fails on first attempts, then succeeds
	attemptCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount++
		if attemptCount < 3 {
			http.Error(w, "temporary failure", http.StatusServiceUnavailable)
			return
		}
		_, err := w.Write(binaryContent)
		require.NoError(t, err)
	}))
	defer server.Close()

	source := &GitHubSource{
		Owner:           "test",
		Repo:            "test",
		DownloadBaseURL: server.URL,
	}

	var buf bytes.Buffer
	err := source.Download(context.Background(), "v1.0.0", "test.tar.gz", &buf)
	require.NoError(t, err)
	assert.Equal(t, binaryContent, buf.Bytes())
	assert.GreaterOrEqual(t, attemptCount, 3, "expected at least 3 attempts (failures + success)")
}

func TestGitHubDownloadFailsAfterMaxRetries(t *testing.T) {
	// Server always returns 503 (retryable by go-retryablehttp)
	attemptCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount++
		http.Error(w, "permanent failure", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	source := &GitHubSource{
		Owner:           "test",
		Repo:            "test",
		DownloadBaseURL: server.URL,
	}

	var buf bytes.Buffer
	err := source.Download(context.Background(), "v1.0.0", "test.tar.gz", &buf)
	require.Error(t, err)

	assert.Equal(t, 4, attemptCount, "expected 4 total attempts (1 initial + 3 retries)")
}

func TestGitHubDownloadSuccess(t *testing.T) {
	binaryContent := []byte("successful download content")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write(binaryContent)
		require.NoError(t, err)
	}))
	defer server.Close()

	source := &GitHubSource{
		Owner:           "test",
		Repo:            "test",
		DownloadBaseURL: server.URL,
	}

	var buf bytes.Buffer
	err := source.Download(context.Background(), "v1.0.0", "test.tar.gz", &buf)
	require.NoError(t, err)
	assert.Equal(t, binaryContent, buf.Bytes())
}
