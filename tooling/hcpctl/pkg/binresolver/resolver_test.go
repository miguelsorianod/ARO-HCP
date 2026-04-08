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
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testSource struct {
	version    string // returned by LatestTagName
	versionErr error  // if set, LatestTagName returns this error
	serverURL  string // base URL for downloads
}

func (s *testSource) LatestTagName(_ context.Context) (string, error) {
	if s.versionErr != nil {
		return "", s.versionErr
	}
	return s.version, nil
}

func (s *testSource) Download(ctx context.Context, version, asset string, w io.Writer) error {
	url := s.serverURL + "/" + version + "/" + asset
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned status %d for %s", resp.StatusCode, url)
	}
	_, err = io.Copy(w, resp.Body)
	return err
}

func setupTestDownloadServer(t *testing.T, assets map[string][]byte) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if data, ok := assets[r.URL.Path]; ok {
			_, err := w.Write(data)
			require.NoError(t, err)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)
	return server
}

func testConfig(t *testing.T) *resolverConfig {
	t.Helper()
	return &resolverConfig{
		cacheRoot: t.TempDir(),
	}
}

func TestAssetName(t *testing.T) {
	spec := BinarySpec{
		Name:         "must-gather-clean",
		AssetPattern: "{name}-{os}-{arch}.tar.gz",
	}

	result := assetName(spec)
	expected := "must-gather-clean-" + runtime.GOOS + "-" + runtime.GOARCH + ".tar.gz"
	assert.Equal(t, expected, result)
}

func TestResolveWithExplicitPath(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(t *testing.T) string
		expectError bool
	}{
		{
			name: "explicit path exists",
			setup: func(t *testing.T) string {
				tmpFile := filepath.Join(t.TempDir(), "must-gather-clean")
				require.NoError(t, os.WriteFile(tmpFile, []byte("binary"), 0755))
				return tmpFile
			},
			expectError: false,
		},
		{
			name: "explicit path does not exist",
			setup: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "nonexistent")
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig(t)
			path := tt.setup(t)
			result, err := cfg.resolve(context.Background(), MustGatherClean, path)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, path, result)
			}
		})
	}
}

func TestResolveExplicitPathLogsMessage(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "must-gather-clean")
	require.NoError(t, os.WriteFile(tmpFile, []byte("binary"), 0755))

	var logMessages []string
	logger := funcr.New(func(prefix, args string) {
		logMessages = append(logMessages, args)
	}, funcr.Options{Verbosity: 1})

	ctx := logr.NewContext(context.Background(), logger)
	cfg := testConfig(t)
	result, err := cfg.resolve(ctx, MustGatherClean, tmpFile)

	require.NoError(t, err)
	assert.Equal(t, tmpFile, result)

	found := false
	for _, msg := range logMessages {
		if strings.Contains(msg, "using explicit binary path") {
			found = true
			break
		}
	}
	assert.True(t, found, "expected log message about explicit path, got: %v", logMessages)
}

func TestResolveWithoutSourceReturnsError(t *testing.T) {
	cfg := testConfig(t)
	spec := BinarySpec{
		Name:         "test-binary",
		AssetPattern: "{name}-{os}-{arch}.tar.gz",
	}

	_, err := cfg.resolve(context.Background(), spec, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no source configured")
}

func TestResolveRejectsInvalidVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
	}{
		{"path traversal with dots", "../../../etc/passwd"},
		{"path traversal with slash", "v1.0.0/../../evil"},
		{"backslash traversal", `v1.0.0\..\evil`},
		{"trailing dot-dot", "v1.0.0/.."},
		{"query string injection", "v1.0.0?malicious=true"},
		{"fragment injection", "v1.0.0#fragment"},
		{"space in version", "v1.0.0 evil"},
		{"newline in version", "v1.0.0\nevil"},
		{"null byte in version", "v1.0.0\x00evil"},
		{"tab in version", "v1.0.0\tevil"},
		{"carriage return", "v1.0.0\revil"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig(t)
			spec := BinarySpec{
				Name:         "test-binary",
				Source:       &testSource{version: tt.version},
				AssetPattern: "{name}-{os}-{arch}.tar.gz",
			}

			_, err := cfg.resolve(context.Background(), spec, "")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "invalid version string")
		})
	}
}

func TestResolveAcceptsDoubleDotInVersionName(t *testing.T) {
	binaryContent := []byte("#!/bin/sh\necho hello\n")
	tarGzData := createTestTarGz(t, "test-binary", binaryContent)

	spec := BinarySpec{
		Name:         "test-binary",
		AssetPattern: "{name}-{os}-{arch}.tar.gz",
	}
	asset := assetName(spec)

	server := setupTestDownloadServer(t, map[string][]byte{
		"/v1..0/" + asset: tarGzData,
	})
	spec.Source = &testSource{version: "v1..0", serverURL: server.URL}
	cfg := testConfig(t)

	result, err := cfg.resolve(context.Background(), spec, "")
	require.NoError(t, err)
	assert.NotEmpty(t, result)
}

func TestLimitedWriter(t *testing.T) {
	t.Run("within limit", func(t *testing.T) {
		var buf bytes.Buffer
		lw := &limitedWriter{w: &buf, limit: 100}
		n, err := lw.Write([]byte("hello"))
		require.NoError(t, err)
		assert.Equal(t, 5, n)
		assert.False(t, lw.overflow)
		assert.Equal(t, "hello", buf.String())
	})

	t.Run("exceeds limit", func(t *testing.T) {
		var buf bytes.Buffer
		lw := &limitedWriter{w: &buf, limit: 3}
		n, err := lw.Write([]byte("hello"))
		require.NoError(t, err)
		assert.Equal(t, 5, n)
		assert.True(t, lw.overflow)
		assert.Empty(t, buf.String())
	})

	t.Run("exact limit", func(t *testing.T) {
		var buf bytes.Buffer
		lw := &limitedWriter{w: &buf, limit: 5}
		n, err := lw.Write([]byte("hello"))
		require.NoError(t, err)
		assert.Equal(t, 5, n)
		assert.False(t, lw.overflow)
		assert.Equal(t, "hello", buf.String())
	})

	t.Run("multiple writes exceeding limit", func(t *testing.T) {
		var buf bytes.Buffer
		lw := &limitedWriter{w: &buf, limit: 8}
		_, err := lw.Write([]byte("hello"))
		require.NoError(t, err)
		assert.False(t, lw.overflow)

		_, err = lw.Write([]byte("world"))
		require.NoError(t, err)
		assert.True(t, lw.overflow)
		assert.Equal(t, "hello", buf.String())
	})
}

func TestChecksumRejectsOversizedChecksumFile(t *testing.T) {
	binaryContent := []byte("#!/bin/sh\necho hello\n")
	tarGzData := createTestTarGz(t, "test-binary", binaryContent)

	spec := BinarySpec{
		Name:          "test-binary",
		AssetPattern:  "{name}-{os}-{arch}.tar.gz",
		ChecksumAsset: "SHA256_SUM",
	}
	asset := assetName(spec)

	// Create a checksum file that exceeds maxChecksumFileSize
	oversizedChecksum := strings.Repeat("x", maxChecksumFileSize+1)
	server := setupTestDownloadServer(t, map[string][]byte{
		"/v1.0.0/" + asset:   tarGzData,
		"/v1.0.0/SHA256_SUM": []byte(oversizedChecksum),
	})
	spec.Source = &testSource{version: "v1.0.0", serverURL: server.URL}
	cfg := testConfig(t)

	_, err := cfg.resolve(context.Background(), spec, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum allowed size")
}

func TestResolveAutoDownload(t *testing.T) {
	binaryContent := []byte("#!/bin/sh\necho hello\n")
	tarGzData := createTestTarGz(t, "test-binary", binaryContent)

	spec := BinarySpec{
		Name:         "test-binary",
		AssetPattern: "{name}-{os}-{arch}.tar.gz",
	}
	asset := assetName(spec)

	var downloadCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1.0.0/"+asset {
			downloadCount++
			_, err := w.Write(tarGzData)
			require.NoError(t, err)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)

	spec.Source = &testSource{version: "v1.0.0", serverURL: server.URL}
	cfg := testConfig(t)

	// First resolve — should download
	result, err := cfg.resolve(context.Background(), spec, "")
	require.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Equal(t, 1, downloadCount, "first resolve should download")

	// Verify the binary was written
	content, err := os.ReadFile(result)
	require.NoError(t, err)
	assert.Equal(t, binaryContent, content)

	// Verify .version file was written
	cachedVer, err := cfg.readCachedVersion(spec)
	require.NoError(t, err)
	assert.Equal(t, "v1.0.0", cachedVer)

	// Second resolve — should use cache (no download)
	result2, err := cfg.resolve(context.Background(), spec, "")
	require.NoError(t, err)
	assert.Equal(t, result, result2)
	assert.Equal(t, 1, downloadCount, "second resolve should skip download (cache hit)")
}

func TestResolveCacheHitSkipsDownload(t *testing.T) {
	binaryContent := []byte("#!/bin/sh\necho hello\n")
	tarGzData := createTestTarGz(t, "test-binary", binaryContent)

	spec := BinarySpec{
		Name:         "test-binary",
		AssetPattern: "{name}-{os}-{arch}.tar.gz",
	}
	asset := assetName(spec)

	var downloadCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1.0.0/"+asset {
			downloadCount++
			_, err := w.Write(tarGzData)
			require.NoError(t, err)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)

	spec.Source = &testSource{version: "v1.0.0", serverURL: server.URL}
	cfg := testConfig(t)

	// First resolve downloads
	_, err := cfg.resolve(context.Background(), spec, "")
	require.NoError(t, err)
	assert.Equal(t, 1, downloadCount)

	// Resolve 5 more times — none should download
	for i := 0; i < 5; i++ {
		_, err := cfg.resolve(context.Background(), spec, "")
		require.NoError(t, err)
	}
	assert.Equal(t, 1, downloadCount, "repeated resolves with same version should not download")
}

func TestResolveDownloadsWhenVersionDiffers(t *testing.T) {
	content1 := []byte("#!/bin/sh\necho v1\n")
	content2 := []byte("#!/bin/sh\necho v2\n")

	spec := BinarySpec{
		Name:         "test-binary",
		AssetPattern: "{name}-{os}-{arch}.tar.gz",
	}
	asset := assetName(spec)

	tarGz1 := createTestTarGz(t, "test-binary", content1)
	tarGz2 := createTestTarGz(t, "test-binary", content2)

	server := setupTestDownloadServer(t, map[string][]byte{
		"/v1.0.0/" + asset: tarGz1,
		"/v2.0.0/" + asset: tarGz2,
	})

	cfg := testConfig(t)

	// Download v1.0.0
	spec.Source = &testSource{version: "v1.0.0", serverURL: server.URL}
	result1, err := cfg.resolve(context.Background(), spec, "")
	require.NoError(t, err)
	c1, _ := os.ReadFile(result1)
	assert.Equal(t, content1, c1)

	ver1, _ := cfg.readCachedVersion(spec)
	assert.Equal(t, "v1.0.0", ver1)

	// Source now returns v2.0.0 — should re-download
	spec.Source = &testSource{version: "v2.0.0", serverURL: server.URL}
	result2, err := cfg.resolve(context.Background(), spec, "")
	require.NoError(t, err)
	assert.Equal(t, result1, result2, "same cache path")

	c2, _ := os.ReadFile(result2)
	assert.Equal(t, content2, c2)

	ver2, _ := cfg.readCachedVersion(spec)
	assert.Equal(t, "v2.0.0", ver2)
}

func TestResolveDownloadsWhenVersionFileMissing(t *testing.T) {
	binaryContent := []byte("#!/bin/sh\necho hello\n")
	tarGzData := createTestTarGz(t, "test-binary", binaryContent)

	spec := BinarySpec{
		Name:         "test-binary",
		AssetPattern: "{name}-{os}-{arch}.tar.gz",
	}
	asset := assetName(spec)

	var downloadCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1.0.0/"+asset {
			downloadCount++
			_, err := w.Write(tarGzData)
			require.NoError(t, err)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)

	spec.Source = &testSource{version: "v1.0.0", serverURL: server.URL}
	cfg := testConfig(t)

	// First download
	_, err := cfg.resolve(context.Background(), spec, "")
	require.NoError(t, err)
	assert.Equal(t, 1, downloadCount)

	// Delete .version file
	versionPath, _ := cfg.cachedVersionPath(spec)
	require.NoError(t, os.Remove(versionPath))

	// Should re-download since version is unknown
	_, err = cfg.resolve(context.Background(), spec, "")
	require.NoError(t, err)
	assert.Equal(t, 2, downloadCount, "missing .version file should trigger re-download")
}

func TestResolveDownloadsWhenVersionFileCorrupted(t *testing.T) {
	binaryContent := []byte("#!/bin/sh\necho hello\n")
	tarGzData := createTestTarGz(t, "test-binary", binaryContent)

	spec := BinarySpec{
		Name:         "test-binary",
		AssetPattern: "{name}-{os}-{arch}.tar.gz",
	}
	asset := assetName(spec)

	server := setupTestDownloadServer(t, map[string][]byte{
		"/v1.0.0/" + asset: tarGzData,
	})
	spec.Source = &testSource{version: "v1.0.0", serverURL: server.URL}
	cfg := testConfig(t)

	// First download
	_, err := cfg.resolve(context.Background(), spec, "")
	require.NoError(t, err)

	// Corrupt .version file with path traversal content
	versionPath, _ := cfg.cachedVersionPath(spec)
	require.NoError(t, os.WriteFile(versionPath, []byte("../../../etc/evil\n"), 0644))

	// Should re-download since version is invalid
	_, err = cfg.resolve(context.Background(), spec, "")
	require.NoError(t, err)

	// Version should now be correct
	ver, _ := cfg.readCachedVersion(spec)
	assert.Equal(t, "v1.0.0", ver)
}

func TestResolveDownloadsWhenBinaryMissingButVersionExists(t *testing.T) {
	binaryContent := []byte("#!/bin/sh\necho hello\n")
	tarGzData := createTestTarGz(t, "test-binary", binaryContent)

	spec := BinarySpec{
		Name:         "test-binary",
		AssetPattern: "{name}-{os}-{arch}.tar.gz",
	}
	asset := assetName(spec)

	server := setupTestDownloadServer(t, map[string][]byte{
		"/v1.0.0/" + asset: tarGzData,
	})
	spec.Source = &testSource{version: "v1.0.0", serverURL: server.URL}
	cfg := testConfig(t)

	// First download
	result, err := cfg.resolve(context.Background(), spec, "")
	require.NoError(t, err)

	// Delete binary but leave .version
	require.NoError(t, os.Remove(result))

	// Should re-download
	result2, err := cfg.resolve(context.Background(), spec, "")
	require.NoError(t, err)
	assert.Equal(t, result, result2)

	content, _ := os.ReadFile(result2)
	assert.Equal(t, binaryContent, content)
}

func TestResolveOfflineFallbackLogsVersion(t *testing.T) {
	cfg := testConfig(t)
	spec := BinarySpec{
		Name:         "test-binary",
		Source:       &testSource{versionErr: fmt.Errorf("unreachable")},
		AssetPattern: "{name}-{os}-{arch}.tar.gz",
	}

	// Pre-populate cache with binary and .version
	cacheDir, _ := cfg.cacheBaseDir(spec)
	require.NoError(t, os.MkdirAll(cacheDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(cacheDir, "test-binary"), []byte("bin"), 0755))
	require.NoError(t, cfg.writeCachedVersion(spec, "v1.2.3"))

	var logMessages []string
	logger := funcr.New(func(_, args string) {
		logMessages = append(logMessages, args)
	}, funcr.Options{Verbosity: 4})
	ctx := logr.NewContext(context.Background(), logger)

	_, err := cfg.resolve(ctx, spec, "")
	require.NoError(t, err)

	found := false
	for _, msg := range logMessages {
		if strings.Contains(msg, "source unreachable") && strings.Contains(msg, "v1.2.3") {
			found = true
			break
		}
	}
	assert.True(t, found, "expected log with version, got: %v", logMessages)
}

func TestResolveCacheHitWithNonSemverVersion(t *testing.T) {
	binaryContent := []byte("#!/bin/sh\necho hello\n")
	tarGzData := createTestTarGz(t, "test-binary", binaryContent)

	spec := BinarySpec{
		Name:         "test-binary",
		AssetPattern: "{name}-{os}-{arch}.tar.gz",
	}
	asset := assetName(spec)

	var downloadCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/abc123def/"+asset {
			downloadCount++
			_, err := w.Write(tarGzData)
			require.NoError(t, err)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)

	// Source returns a commit hash instead of semver
	spec.Source = &testSource{version: "abc123def", serverURL: server.URL}
	cfg := testConfig(t)

	// First resolve downloads
	_, err := cfg.resolve(context.Background(), spec, "")
	require.NoError(t, err)
	assert.Equal(t, 1, downloadCount)

	ver, _ := cfg.readCachedVersion(spec)
	assert.Equal(t, "abc123def", ver)

	// Second resolve — cache hit (non-semver version works)
	_, err = cfg.resolve(context.Background(), spec, "")
	require.NoError(t, err)
	assert.Equal(t, 1, downloadCount, "non-semver version should still cache hit")
}

func TestResolvePinnedVersion(t *testing.T) {
	binaryContent := []byte("#!/bin/sh\necho pinned\n")
	tarGzData := createTestTarGz(t, "test-binary", binaryContent)

	spec := BinarySpec{
		Name:          "test-binary",
		AssetPattern:  "{name}-{os}-{arch}.tar.gz",
		PinnedVersion: "v0.5.0",
	}
	asset := assetName(spec)

	var latestQueried bool
	var downloadCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "releases/latest") {
			latestQueried = true
		}
		if r.URL.Path == "/v0.5.0/"+asset {
			downloadCount++
			_, err := w.Write(tarGzData)
			require.NoError(t, err)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)

	spec.Source = &testSource{version: "v1.0.0", serverURL: server.URL}
	cfg := testConfig(t)

	// Should download v0.5.0 (pinned), NOT query for latest
	result, err := cfg.resolve(context.Background(), spec, "")
	require.NoError(t, err)
	assert.False(t, latestQueried, "pinned version should NOT query source for latest")
	assert.Equal(t, 1, downloadCount)

	content, _ := os.ReadFile(result)
	assert.Equal(t, binaryContent, content)

	ver, _ := cfg.readCachedVersion(spec)
	assert.Equal(t, "v0.5.0", ver)

	// Second resolve — cache hit (pinned version matches cache)
	_, err = cfg.resolve(context.Background(), spec, "")
	require.NoError(t, err)
	assert.Equal(t, 1, downloadCount, "pinned version cache hit should skip download")
}

func TestResolvePinnedVersionSkipsSourceEntirely(t *testing.T) {
	binaryContent := []byte("#!/bin/sh\necho pinned\n")
	tarGzData := createTestTarGz(t, "test-binary", binaryContent)

	spec := BinarySpec{
		Name:          "test-binary",
		AssetPattern:  "{name}-{os}-{arch}.tar.gz",
		PinnedVersion: "v0.5.0",
	}
	asset := assetName(spec)

	server := setupTestDownloadServer(t, map[string][]byte{
		"/v0.5.0/" + asset: tarGzData,
	})

	// Source that would error on LatestTagName — but pinned version never calls it
	spec.Source = &testSource{versionErr: fmt.Errorf("source is down"), serverURL: server.URL}
	cfg := testConfig(t)

	// Should succeed despite source being "down" for version queries
	result, err := cfg.resolve(context.Background(), spec, "")
	require.NoError(t, err)

	content, _ := os.ReadFile(result)
	assert.Equal(t, binaryContent, content)
}

func TestResolvePinnedVersionOfflineAfterCache(t *testing.T) {
	binaryContent := []byte("#!/bin/sh\necho pinned\n")
	tarGzData := createTestTarGz(t, "test-binary", binaryContent)

	spec := BinarySpec{
		Name:          "test-binary",
		AssetPattern:  "{name}-{os}-{arch}.tar.gz",
		PinnedVersion: "v0.5.0",
	}
	asset := assetName(spec)

	server := setupTestDownloadServer(t, map[string][]byte{
		"/v0.5.0/" + asset: tarGzData,
	})
	spec.Source = &testSource{version: "v1.0.0", serverURL: server.URL}
	cfg := testConfig(t)

	// First download with network
	_, err := cfg.resolve(context.Background(), spec, "")
	require.NoError(t, err)

	// Now source is completely down — pinned version should still work from cache
	spec.Source = &testSource{versionErr: fmt.Errorf("offline"), serverURL: "http://localhost:1"}
	result, err := cfg.resolve(context.Background(), spec, "")
	require.NoError(t, err)

	content, _ := os.ReadFile(result)
	assert.Equal(t, binaryContent, content, "pinned version should work fully offline once cached")
}

func TestResolvePinnedVersionRejectsInvalid(t *testing.T) {
	cfg := testConfig(t)
	spec := BinarySpec{
		Name:          "test-binary",
		Source:        &testSource{version: "v1.0.0"},
		AssetPattern:  "{name}-{os}-{arch}.tar.gz",
		PinnedVersion: "../../../etc/evil",
	}

	_, err := cfg.resolve(context.Background(), spec, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid pinned version")
}

func TestResolveOfflineFallback(t *testing.T) {
	spec := BinarySpec{
		Name:         "test-binary-offline",
		Source:       &testSource{versionErr: fmt.Errorf("unreachable")},
		AssetPattern: "{name}-{os}-{arch}.tar.gz",
	}

	cfg := testConfig(t)

	cacheDir, err := cfg.cacheBaseDir(spec)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(cacheDir, 0755))
	cachedBin := filepath.Join(cacheDir, "test-binary-offline")
	require.NoError(t, os.WriteFile(cachedBin, []byte("cached-binary"), 0755))

	var logMessages []string
	logger := funcr.New(func(prefix, args string) {
		logMessages = append(logMessages, args)
	}, funcr.Options{Verbosity: 4})
	ctx := logr.NewContext(context.Background(), logger)

	result, err := cfg.resolve(ctx, spec, "")
	require.NoError(t, err)
	assert.Equal(t, cachedBin, result)

	found := false
	for _, msg := range logMessages {
		if strings.Contains(msg, "cached binary") && strings.Contains(msg, "source unreachable") {
			found = true
			break
		}
	}
	assert.True(t, found, "expected warning about cached binary, got: %v", logMessages)
}

func TestChecksumVerification(t *testing.T) {
	binaryContent := []byte("#!/bin/sh\necho hello\n")
	tarGzData := createTestTarGz(t, "test-binary", binaryContent)
	expectedHash := fmt.Sprintf("%x", sha256.Sum256(tarGzData))

	spec := BinarySpec{
		Name:          "test-binary",
		AssetPattern:  "{name}-{os}-{arch}.tar.gz",
		ChecksumAsset: "SHA256_SUM",
	}
	asset := assetName(spec)

	t.Run("valid checksum", func(t *testing.T) {
		checksumContent := fmt.Sprintf("%s %s\n", expectedHash, asset)
		server := setupTestDownloadServer(t, map[string][]byte{
			"/v1.0.0/" + asset:   tarGzData,
			"/v1.0.0/SHA256_SUM": []byte(checksumContent),
		})
		spec := spec // copy
		spec.Source = &testSource{version: "v1.0.0", serverURL: server.URL}
		cfg := testConfig(t)

		result, err := cfg.resolve(context.Background(), spec, "")
		require.NoError(t, err)
		assert.NotEmpty(t, result)

		content, err := os.ReadFile(result)
		require.NoError(t, err)
		assert.Equal(t, binaryContent, content)
	})

	t.Run("invalid checksum", func(t *testing.T) {
		badChecksum := "0000000000000000000000000000000000000000000000000000000000000000"
		server := setupTestDownloadServer(t, map[string][]byte{
			"/v1.0.0/" + asset:   tarGzData,
			"/v1.0.0/SHA256_SUM": []byte(fmt.Sprintf("%s %s\n", badChecksum, asset)),
		})
		spec := spec
		spec.Source = &testSource{version: "v1.0.0", serverURL: server.URL}
		cfg := testConfig(t)

		_, err := cfg.resolve(context.Background(), spec, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "checksum mismatch")
	})

	t.Run("checksum file unavailable", func(t *testing.T) {
		server := setupTestDownloadServer(t, map[string][]byte{
			"/v1.0.0/" + asset: tarGzData,
			// no checksum file — server returns 404
		})
		spec := spec
		spec.Source = &testSource{version: "v1.0.0", serverURL: server.URL}
		cfg := testConfig(t)

		_, err := cfg.resolve(context.Background(), spec, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "checksum")
	})

	t.Run("checksum asset missing from checksum file", func(t *testing.T) {
		checksumContent := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa unrelated-tool-linux-amd64.tar.gz\n"
		server := setupTestDownloadServer(t, map[string][]byte{
			"/v1.0.0/" + asset:   tarGzData,
			"/v1.0.0/SHA256_SUM": []byte(checksumContent),
		})
		spec := spec
		spec.Source = &testSource{version: "v1.0.0", serverURL: server.URL}
		cfg := testConfig(t)

		_, err := cfg.resolve(context.Background(), spec, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found in checksum file")
	})
}

func TestChecksumVerificationDifferentBinary(t *testing.T) {
	binaryContent := []byte("different-tool-binary-content")
	tarGzData := createTestTarGz(t, "other-tool", binaryContent)
	correctHash := fmt.Sprintf("%x", sha256.Sum256(tarGzData))

	spec := BinarySpec{
		Name:          "other-tool",
		AssetPattern:  "{name}-{os}-{arch}.tar.gz",
		ChecksumAsset: "checksums.txt",
	}
	asset := assetName(spec)

	t.Run("picks correct entry from multi-asset checksum file", func(t *testing.T) {
		checksumContent := fmt.Sprintf(
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa unrelated-tool-linux-amd64.tar.gz\n"+
				"%s %s\n"+
				"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb another-tool-darwin-arm64.tar.gz\n",
			correctHash, asset)

		server := setupTestDownloadServer(t, map[string][]byte{
			"/v2.0.0/" + asset:      tarGzData,
			"/v2.0.0/checksums.txt": []byte(checksumContent),
		})
		spec := spec
		spec.Source = &testSource{version: "v2.0.0", serverURL: server.URL}
		cfg := testConfig(t)

		result, err := cfg.resolve(context.Background(), spec, "")
		require.NoError(t, err)

		content, err := os.ReadFile(result)
		require.NoError(t, err)
		assert.Equal(t, binaryContent, content)
	})

	t.Run("wrong archive detected via checksum", func(t *testing.T) {
		wrongHash := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
		server := setupTestDownloadServer(t, map[string][]byte{
			"/v2.0.0/" + asset:      tarGzData,
			"/v2.0.0/checksums.txt": []byte(fmt.Sprintf("%s %s\n", wrongHash, asset)),
		})
		spec := spec
		spec.Source = &testSource{version: "v2.0.0", serverURL: server.URL}
		cfg := testConfig(t)

		_, err := cfg.resolve(context.Background(), spec, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "checksum mismatch")
	})
}

func TestResolveSkipsChecksumWhenNotConfigured(t *testing.T) {
	binaryContent := []byte("no-checksum-binary")
	tarGzData := createTestTarGz(t, "test-binary", binaryContent)

	spec := BinarySpec{
		Name:         "test-binary",
		AssetPattern: "{name}-{os}-{arch}.tar.gz",
		// no ChecksumAsset
	}
	asset := assetName(spec)

	checksumRequested := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "SHA256") || strings.Contains(r.URL.Path, "checksum") {
			checksumRequested = true
		}
		path := "/v1.0.0/" + asset
		if r.URL.Path == path {
			_, err := w.Write(tarGzData)
			require.NoError(t, err)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	spec.Source = &testSource{version: "v1.0.0", serverURL: server.URL}
	cfg := testConfig(t)

	result, err := cfg.resolve(context.Background(), spec, "")
	require.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.False(t, checksumRequested, "checksum file should not be requested when ChecksumAsset is empty")

	content, err := os.ReadFile(result)
	require.NoError(t, err)
	assert.Equal(t, binaryContent, content)
}

func TestFindAnyCachedReturnsCachedBinary(t *testing.T) {
	cfg := testConfig(t)
	spec := BinarySpec{Name: "test-binary"}

	baseDir, err := cfg.cacheBaseDir(spec)
	require.NoError(t, err)

	binPath := filepath.Join(baseDir, "test-binary")
	require.NoError(t, os.MkdirAll(baseDir, 0755))
	require.NoError(t, os.WriteFile(binPath, []byte("cached-bin"), 0755))

	result, err := cfg.findAnyCached(spec)
	require.NoError(t, err)
	assert.Equal(t, binPath, result)

	content, err := os.ReadFile(result)
	require.NoError(t, err)
	assert.Equal(t, []byte("cached-bin"), content)
}

func TestDownloadReturns404ForUnsupportedPlatform(t *testing.T) {
	// Server returns 404 for all downloads
	server := setupTestDownloadServer(t, map[string][]byte{})

	spec := BinarySpec{
		Name:         "test-tool",
		Source:       &testSource{version: "v1.0.0", serverURL: server.URL},
		AssetPattern: "{name}-{os}-{arch}.tar.gz",
	}
	cfg := testConfig(t)

	_, err := cfg.resolve(context.Background(), spec, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "404")
	assert.Contains(t, err.Error(), runtime.GOOS+"/"+runtime.GOARCH)
	assert.Contains(t, err.Error(), "--test-tool-binary")
}

func TestFindAnyCachedNoCacheDir(t *testing.T) {
	cfg := &resolverConfig{
		cacheRoot: filepath.Join(t.TempDir(), "nonexistent"),
	}
	spec := BinarySpec{Name: "nonexistent-binary-" + t.Name()}
	_, err := cfg.findAnyCached(spec)
	assert.Error(t, err)
}

func TestCacheBaseDirUsesEnvVar(t *testing.T) {
	customDir := filepath.Join(t.TempDir(), "custom-cache")
	t.Setenv("HCPCTL_CACHE_DIR", customDir)

	cfg := &resolverConfig{}
	spec := BinarySpec{Name: "test-binary"}

	baseDir, err := cfg.cacheBaseDir(spec)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(customDir, "test-binary"), baseDir)
}

func TestCacheBaseDirExplicitRootOverridesEnvVar(t *testing.T) {
	explicitDir := filepath.Join(t.TempDir(), "explicit-cache")
	envDir := filepath.Join(t.TempDir(), "env-cache")
	t.Setenv("HCPCTL_CACHE_DIR", envDir)

	cfg := &resolverConfig{cacheRoot: explicitDir}
	spec := BinarySpec{Name: "test-binary"}

	baseDir, err := cfg.cacheBaseDir(spec)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(explicitDir, "test-binary"), baseDir)
}

func TestResolveCacheDirParameter(t *testing.T) {
	binaryContent := []byte("#!/bin/sh\necho hello\n")
	tarGzData := createTestTarGz(t, "test-binary", binaryContent)

	spec := BinarySpec{
		Name:         "test-binary",
		AssetPattern: "{name}-{os}-{arch}.tar.gz",
	}
	asset := assetName(spec)

	server := setupTestDownloadServer(t, map[string][]byte{
		"/v1.0.0/" + asset: tarGzData,
	})
	spec.Source = &testSource{version: "v1.0.0", serverURL: server.URL}

	customDir := t.TempDir()
	result, err := Resolve(context.Background(), spec, "", customDir)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(result, customDir),
		"binary should be cached in the provided cacheDir, got %q", result)
}

func TestResolveAutoDownloadZip(t *testing.T) {
	binaryContent := []byte("#!/bin/sh\necho hello from zip\n")
	zipData := createTestZip(t, "test-binary", binaryContent)

	spec := BinarySpec{
		Name:         "test-binary",
		AssetPattern: "{name}-{os}-{arch}.zip",
	}
	asset := assetName(spec)

	server := setupTestDownloadServer(t, map[string][]byte{
		"/v1.0.0/" + asset: zipData,
	})
	spec.Source = &testSource{version: "v1.0.0", serverURL: server.URL}
	cfg := testConfig(t)

	result, err := cfg.resolve(context.Background(), spec, "")
	require.NoError(t, err)
	assert.NotEmpty(t, result)

	content, err := os.ReadFile(result)
	require.NoError(t, err)
	assert.Equal(t, binaryContent, content)
}

func TestExtractTarGzBinaryNotFound(t *testing.T) {
	tarGzData := createTestTarGz(t, "other-binary", []byte("content"))
	archivePath := filepath.Join(t.TempDir(), "test.tar.gz")
	require.NoError(t, os.WriteFile(archivePath, tarGzData, 0644))

	destPath := filepath.Join(t.TempDir(), "expected-binary")
	err := extractTarGz(archivePath, "expected-binary", destPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found in archive")
}

func TestExtractTarGzCorruptedArchive(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "corrupt.tar.gz")
	require.NoError(t, os.WriteFile(archivePath, []byte("not a real archive"), 0644))

	destPath := filepath.Join(t.TempDir(), "binary")
	err := extractTarGz(archivePath, "binary", destPath)
	require.Error(t, err)
}

func TestExtractZipBinaryNotFound(t *testing.T) {
	zipData := createTestZip(t, "other-binary", []byte("content"))
	archivePath := filepath.Join(t.TempDir(), "test.zip")
	require.NoError(t, os.WriteFile(archivePath, zipData, 0644))

	destPath := filepath.Join(t.TempDir(), "expected-binary")
	err := extractZip(archivePath, "expected-binary", destPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found in zip archive")
}

func createTestZip(t *testing.T, binaryName string, content []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	fw, err := zw.Create(binaryName)
	require.NoError(t, err)
	_, err = fw.Write(content)
	require.NoError(t, err)
	require.NoError(t, zw.Close())

	return buf.Bytes()
}

func createTestTarGz(t *testing.T, binaryName string, content []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	header := &tar.Header{
		Name: binaryName,
		Mode: 0755,
		Size: int64(len(content)),
	}
	require.NoError(t, tw.WriteHeader(header))
	_, err := tw.Write(content)
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())

	return buf.Bytes()
}
