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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testSource struct {
	version    string // returned by LatestVersion
	versionErr error  // if set, LatestVersion returns this error
	serverURL  string // base URL for downloads
}

func (s *testSource) LatestVersion(_ context.Context, _ *http.Client) (string, error) {
	if s.versionErr != nil {
		return "", s.versionErr
	}
	return s.version, nil
}

func (s *testSource) DownloadURL(version, asset string) string {
	return s.serverURL + "/" + version + "/" + asset
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
		cacheRoot:  t.TempDir(),
		httpClient: http.DefaultClient,
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

func TestResolveAutoDownload(t *testing.T) {
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

	// Resolve without explicit path — should auto-download
	result, err := cfg.resolve(context.Background(), spec, "")
	require.NoError(t, err)
	assert.NotEmpty(t, result)

	// Verify the binary was written
	content, err := os.ReadFile(result)
	require.NoError(t, err)
	assert.Equal(t, binaryContent, content)

	result2, err := cfg.resolve(context.Background(), spec, "")
	require.NoError(t, err)
	assert.Equal(t, result, result2)
}

func TestResolveOfflineFallback(t *testing.T) {
	spec := BinarySpec{
		Name:         "test-binary-offline",
		Source:       &testSource{versionErr: fmt.Errorf("unreachable")},
		AssetPattern: "{name}-{os}-{arch}.tar.gz",
	}

	cfg := testConfig(t)

	// Pre-populate cache with a binary
	cacheDir, err := cfg.cacheBaseDir(spec)
	require.NoError(t, err)
	versionDir := filepath.Join(cacheDir, "v0.0.1")
	require.NoError(t, os.MkdirAll(versionDir, 0755))
	cachedBin := filepath.Join(versionDir, "test-binary-offline")
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
		if strings.Contains(msg, "cached binary") && strings.Contains(msg, "outdated") {
			found = true
			break
		}
	}
	assert.True(t, found, "expected warning about cached binary, got: %v", logMessages)
}

func TestCleanOldVersions(t *testing.T) {
	cfg := testConfig(t)
	spec := BinarySpec{Name: "test-binary"}

	baseDir, err := cfg.cacheBaseDir(spec)
	require.NoError(t, err)

	for _, v := range []string{"v0.0.1", "v0.0.2", "v0.0.3"} {
		require.NoError(t, os.MkdirAll(filepath.Join(baseDir, v), 0755))
		require.NoError(t, os.WriteFile(filepath.Join(baseDir, v, "test-binary"), []byte("bin"), 0755))
	}

	entries, err := os.ReadDir(baseDir)
	require.NoError(t, err)
	assert.Len(t, entries, 3)

	require.NoError(t, cfg.cleanOldVersions(spec, "v0.0.3"))

	entries, err = os.ReadDir(baseDir)
	require.NoError(t, err)
	assert.Len(t, entries, 1)
	assert.Equal(t, "v0.0.3", entries[0].Name())
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

		var logMessages []string
		logger := funcr.New(func(_ string, args string) {
			logMessages = append(logMessages, args)
		}, funcr.Options{Verbosity: 1})
		ctx := logr.NewContext(context.Background(), logger)

		result, err := cfg.resolve(ctx, spec, "")
		require.NoError(t, err)
		assert.NotEmpty(t, result)

		content, err := os.ReadFile(result)
		require.NoError(t, err)
		assert.Equal(t, binaryContent, content)

		found := false
		for _, msg := range logMessages {
			if strings.Contains(msg, "checksum verification skipped") && strings.Contains(msg, "checksum_unavailable") {
				found = true
				break
			}
		}
		assert.True(t, found, "expected checksum_unavailable warning, got logs: %v", logMessages)
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

		var logMessages []string
		logger := funcr.New(func(_ string, args string) {
			logMessages = append(logMessages, args)
		}, funcr.Options{Verbosity: 1})
		ctx := logr.NewContext(context.Background(), logger)

		result, err := cfg.resolve(ctx, spec, "")
		require.NoError(t, err)
		assert.NotEmpty(t, result)

		content, err := os.ReadFile(result)
		require.NoError(t, err)
		assert.Equal(t, binaryContent, content)

		found := false
		for _, msg := range logMessages {
			if strings.Contains(msg, "checksum verification skipped") && strings.Contains(msg, "asset_not_in_checksum") {
				found = true
				break
			}
		}
		assert.True(t, found, "expected asset_not_in_checksum warning, got logs: %v", logMessages)
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

func TestFindAnyCachedReturnsNewestByModTime(t *testing.T) {
	cfg := testConfig(t)
	spec := BinarySpec{Name: "test-binary"}

	baseDir, err := cfg.cacheBaseDir(spec)
	require.NoError(t, err)

	now := time.Now()
	versions := []string{"v0.0.1", "v0.0.2", "v0.0.3"}
	for i, v := range versions {
		binPath := filepath.Join(baseDir, v, "test-binary")
		require.NoError(t, os.MkdirAll(filepath.Dir(binPath), 0755))
		require.NoError(t, os.WriteFile(binPath, []byte("bin-"+v), 0755))
		modTime := now.Add(time.Duration(i) * time.Minute)
		require.NoError(t, os.Chtimes(binPath, modTime, modTime))
	}

	result, err := cfg.findAnyCached(spec)
	require.NoError(t, err)
	assert.Contains(t, result, "v0.0.3")

	content, err := os.ReadFile(result)
	require.NoError(t, err)
	assert.Equal(t, []byte("bin-v0.0.3"), content)
}

func TestFindAnyCachedPrefersNewestModTimeOverVersionName(t *testing.T) {
	cfg := testConfig(t)
	spec := BinarySpec{Name: "test-binary"}

	baseDir, err := cfg.cacheBaseDir(spec)
	require.NoError(t, err)

	oldPath := filepath.Join(baseDir, "v1.9.0", "test-binary")
	newPath := filepath.Join(baseDir, "v1.10.0", "test-binary")
	require.NoError(t, os.MkdirAll(filepath.Dir(oldPath), 0755))
	require.NoError(t, os.MkdirAll(filepath.Dir(newPath), 0755))
	require.NoError(t, os.WriteFile(oldPath, []byte("old-version"), 0755))
	require.NoError(t, os.WriteFile(newPath, []byte("new-version"), 0755))

	now := time.Now()
	older := now.Add(-1 * time.Hour)
	newer := now.Add(-1 * time.Minute)
	require.NoError(t, os.Chtimes(oldPath, older, older))
	require.NoError(t, os.Chtimes(newPath, newer, newer))

	result, err := cfg.findAnyCached(spec)
	require.NoError(t, err)
	assert.Contains(t, result, "v1.10.0")

	content, err := os.ReadFile(result)
	require.NoError(t, err)
	assert.Equal(t, []byte("new-version"), content)
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
		cacheRoot:  filepath.Join(t.TempDir(), "nonexistent"),
		httpClient: http.DefaultClient,
	}
	spec := BinarySpec{Name: "nonexistent-binary-" + t.Name()}
	_, err := cfg.findAnyCached(spec)
	assert.Error(t, err)
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

func TestResolveAutoDownloadCleansOldVersions(t *testing.T) {
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

	// Pre-populate cache with an old version
	baseDir, err := cfg.cacheBaseDir(spec)
	require.NoError(t, err)
	oldVersionDir := filepath.Join(baseDir, "v0.9.0")
	require.NoError(t, os.MkdirAll(oldVersionDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(oldVersionDir, "test-binary"), []byte("old"), 0755))

	_, err = cfg.resolve(context.Background(), spec, "")
	require.NoError(t, err)

	// Old version should be cleaned up
	entries, err := os.ReadDir(baseDir)
	require.NoError(t, err)
	assert.Len(t, entries, 1)
	assert.Equal(t, "v1.0.0", entries[0].Name())
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
