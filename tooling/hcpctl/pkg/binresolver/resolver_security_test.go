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
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// 1. PATH TRAVERSAL ATTACKS
//    Test that malicious version strings from a compromised GitHub API
//    cannot write binaries outside the cache directory.
// =============================================================================

func TestSecurity_VersionPathTraversal(t *testing.T) {
	maliciousVersions := []string{
		"../../../tmp/pwned",
		"v1.0.0/../../escape",
		"../etc/cron.d/backdoor",
		"v1.0.0/../../../root/.ssh/authorized_keys",
		"..\\..\\Windows\\System32\\evil",
		"v1.0.0/..\\..\\escape",
		"/absolute/path/attempt",
		"v1.0.0\x00injected",
	}

	for _, version := range maliciousVersions {
		t.Run(version, func(t *testing.T) {
			cfg := testConfig(t)
			spec := BinarySpec{
				Name:         "test-binary",
				Source:       &testSource{version: version},
				AssetPattern: "{name}-{os}-{arch}.tar.gz",
			}

			_, err := cfg.resolve(context.Background(), spec, "")
			assert.Error(t, err, "version %q should be rejected", version)
		})
	}
}

func TestSecurity_VersionStringWithNullByte(t *testing.T) {
	cfg := testConfig(t)
	spec := BinarySpec{
		Name:         "test-binary",
		Source:       &testSource{version: "v1.0.0\x00malicious"},
		AssetPattern: "{name}-{os}-{arch}.tar.gz",
	}

	_, err := cfg.resolve(context.Background(), spec, "")
	// Should either error or the null byte should not cause path truncation
	if err == nil {
		t.Error("expected error for version with null byte")
	}
}

// =============================================================================
// 2. TAR SLIP / ZIP SLIP ATTACKS
//    Test that malicious archive entries with path traversal names
//    cannot write files outside the intended destination.
// =============================================================================

func TestSecurity_TarSlipAttack(t *testing.T) {
	// Create a tar.gz with a path-traversal entry name
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	escapeTarget := t.TempDir()

	// Malicious entry trying to escape via ../../
	maliciousContent := []byte("#!/bin/sh\necho PWNED\n")
	header := &tar.Header{
		Name: "../../../../../../" + filepath.Base(escapeTarget) + "/evil-binary",
		Mode: 0755,
		Size: int64(len(maliciousContent)),
	}
	require.NoError(t, tw.WriteHeader(header))
	_, err := tw.Write(maliciousContent)
	require.NoError(t, err)

	// Also include a legitimate entry
	legitimateContent := []byte("#!/bin/sh\necho legit\n")
	header2 := &tar.Header{
		Name: "test-binary",
		Mode: 0755,
		Size: int64(len(legitimateContent)),
	}
	require.NoError(t, tw.WriteHeader(header2))
	_, err = tw.Write(legitimateContent)
	require.NoError(t, err)

	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())

	archivePath := filepath.Join(t.TempDir(), "malicious.tar.gz")
	require.NoError(t, os.WriteFile(archivePath, buf.Bytes(), 0644))

	destDir := t.TempDir()
	destPath := filepath.Join(destDir, "test-binary")

	// The extractor should match only by filepath.Base(), so the malicious
	// entry name "../../.../evil-binary" has Base() == "evil-binary"
	// which does NOT match "test-binary", so it should be skipped.
	err = extractTarGz(archivePath, "test-binary", destPath)
	require.NoError(t, err)

	// Verify the evil binary was NOT written to the escape target
	_, err = os.Stat(filepath.Join(escapeTarget, "evil-binary"))
	assert.True(t, os.IsNotExist(err),
		"SECURITY VULNERABILITY: tar slip attack wrote file outside dest dir")

	// Verify only the legitimate binary was extracted
	content, err := os.ReadFile(destPath)
	require.NoError(t, err)
	assert.Equal(t, legitimateContent, content)
}

func TestSecurity_TarSlipMatchingBinaryName(t *testing.T) {
	// Malicious tar where the binary name matches but has path traversal prefix
	escapeTarget := t.TempDir()

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	maliciousContent := []byte("#!/bin/sh\necho PWNED\n")
	header := &tar.Header{
		Name: "../../../../../../" + filepath.Base(escapeTarget) + "/test-binary",
		Mode: 0755,
		Size: int64(len(maliciousContent)),
	}
	require.NoError(t, tw.WriteHeader(header))
	_, err := tw.Write(maliciousContent)
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())

	archivePath := filepath.Join(t.TempDir(), "malicious.tar.gz")
	require.NoError(t, os.WriteFile(archivePath, buf.Bytes(), 0644))

	destDir := t.TempDir()
	destPath := filepath.Join(destDir, "test-binary")

	// extractTarGz uses filepath.Base(header.Name) == binaryName for matching.
	// This WILL match because Base("../../.../test-binary") == "test-binary".
	// But the write goes to destPath (which is safe), NOT header.Name.
	err = extractTarGz(archivePath, "test-binary", destPath)
	require.NoError(t, err)

	// Verify the binary was written to the safe destination
	content, err := os.ReadFile(destPath)
	require.NoError(t, err)
	assert.Equal(t, maliciousContent, content)

	// Verify nothing was written to the escape target
	_, err = os.Stat(filepath.Join(escapeTarget, "test-binary"))
	assert.True(t, os.IsNotExist(err),
		"tar slip with matching binary name should not write to traversal path")
}

// =============================================================================
// 3. SYMLINK ATTACKS
//    Test that a symlink in the cache directory cannot redirect binary
//    writes to arbitrary filesystem locations.
// =============================================================================

func TestSecurity_SymlinkInCacheDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks require elevated privileges on Windows")
	}
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
	baseDir, err := cfg.cacheBaseDir(spec)
	require.NoError(t, err)

	// Create the cache base dir, then replace it with a symlink to /tmp
	require.NoError(t, os.MkdirAll(baseDir, 0755))
	require.NoError(t, os.RemoveAll(baseDir))

	targetDir := t.TempDir()
	require.NoError(t, os.Symlink(targetDir, baseDir))

	// Resolve should still work, but we need to verify it wrote
	// to the symlink target (which in this case is a controlled temp dir)
	result, err := cfg.resolve(context.Background(), spec, "")
	require.NoError(t, err)

	// The resolved path goes through the symlink - verify the binary content
	// is correct (not corrupted/replaced)
	content, err := os.ReadFile(result)
	require.NoError(t, err)
	assert.Equal(t, binaryContent, content)

	// Verify the binary was actually written to the symlink target
	targetBin := filepath.Join(targetDir, "test-binary")
	_, err = os.Stat(targetBin)
	assert.NoError(t, err, "binary should exist at symlink target")
}

// =============================================================================
// 4. RACE CONDITIONS (TOCTOU)
//    Test that concurrent resolve calls don't corrupt the binary or
//    leave partial writes.
// =============================================================================

func TestSecurity_ConcurrentResolve(t *testing.T) {
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

	const goroutines = 10
	var wg sync.WaitGroup
	results := make([]string, goroutines)
	errs := make([]error, goroutines)

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			results[idx], errs[idx] = cfg.resolve(context.Background(), spec, "")
		}(i)
	}
	wg.Wait()

	// All should succeed
	for i, err := range errs {
		assert.NoError(t, err, "goroutine %d failed", i)
	}

	// All should return the same path
	for i := 1; i < goroutines; i++ {
		assert.Equal(t, results[0], results[i], "goroutine %d returned different path", i)
	}

	// Final binary should have correct content (not corrupted by concurrent writes)
	content, err := os.ReadFile(results[0])
	require.NoError(t, err)
	assert.Equal(t, binaryContent, content, "binary content corrupted by concurrent writes")
}

// =============================================================================
// 5. CHECKSUM BYPASS ATTACKS
//    Test that a tampered binary is rejected when checksums are configured.
// =============================================================================

func TestSecurity_TamperedBinaryWithChecksum(t *testing.T) {
	legitimateContent := []byte("#!/bin/sh\necho legitimate\n")
	legitimateTarGz := createTestTarGz(t, "test-binary", legitimateContent)
	expectedHash := fmt.Sprintf("%x", sha256.Sum256(legitimateTarGz))

	tamperedContent := []byte("#!/bin/sh\nrm -rf / --no-preserve-root\n")
	tamperedTarGz := createTestTarGz(t, "test-binary", tamperedContent)

	spec := BinarySpec{
		Name:          "test-binary",
		AssetPattern:  "{name}-{os}-{arch}.tar.gz",
		ChecksumAsset: "SHA256_SUM",
	}
	asset := assetName(spec)

	// Serve the TAMPERED archive but the LEGITIMATE checksum
	checksumContent := fmt.Sprintf("%s  %s\n", expectedHash, asset)
	server := setupTestDownloadServer(t, map[string][]byte{
		"/v1.0.0/" + asset:   tamperedTarGz,
		"/v1.0.0/SHA256_SUM": []byte(checksumContent),
	})
	spec.Source = &testSource{version: "v1.0.0", serverURL: server.URL}
	cfg := testConfig(t)

	_, err := cfg.resolve(context.Background(), spec, "")
	assert.Error(t, err, "tampered binary should be rejected by checksum verification")
	assert.Contains(t, err.Error(), "checksum mismatch")
}

func TestSecurity_ChecksumBypassViaNoChecksumAsset(t *testing.T) {
	// If ChecksumAsset is empty, checksum verification is skipped entirely.
	// This documents the risk: without checksum config, any binary is accepted.
	tamperedContent := []byte("#!/bin/sh\necho tampered\n")
	tamperedTarGz := createTestTarGz(t, "test-binary", tamperedContent)

	spec := BinarySpec{
		Name:          "test-binary",
		AssetPattern:  "{name}-{os}-{arch}.tar.gz",
		ChecksumAsset: "", // No checksum configured
	}
	asset := assetName(spec)

	server := setupTestDownloadServer(t, map[string][]byte{
		"/v1.0.0/" + asset: tamperedTarGz,
	})
	spec.Source = &testSource{version: "v1.0.0", serverURL: server.URL}
	cfg := testConfig(t)

	// This WILL succeed because no checksum verification is configured.
	// This is expected behavior but documents the risk.
	result, err := cfg.resolve(context.Background(), spec, "")
	assert.NoError(t, err)

	content, err := os.ReadFile(result)
	require.NoError(t, err)
	assert.Equal(t, tamperedContent, content,
		"RISK DOCUMENTATION: without ChecksumAsset, tampered binaries are accepted")
}

func TestSecurity_ChecksumFileWithMaliciousContent(t *testing.T) {
	binaryContent := []byte("#!/bin/sh\necho hello\n")
	tarGzData := createTestTarGz(t, "test-binary", binaryContent)
	correctHash := fmt.Sprintf("%x", sha256.Sum256(tarGzData))

	spec := BinarySpec{
		Name:          "test-binary",
		AssetPattern:  "{name}-{os}-{arch}.tar.gz",
		ChecksumAsset: "SHA256_SUM",
	}
	asset := assetName(spec)

	// Checksum file with extra junk, injection attempts, and the valid hash
	maliciousChecksumContent := strings.Join([]string{
		"not-a-hash some-other-file.tar.gz",
		"<script>alert('xss')</script>",
		"'; DROP TABLE checksums; --",
		correctHash + "  " + asset,
	}, "\n") + "\n"

	server := setupTestDownloadServer(t, map[string][]byte{
		"/v1.0.0/" + asset:   tarGzData,
		"/v1.0.0/SHA256_SUM": []byte(maliciousChecksumContent),
	})
	spec.Source = &testSource{version: "v1.0.0", serverURL: server.URL}
	cfg := testConfig(t)

	// Should still work - parser should skip invalid lines and find the valid hash
	result, err := cfg.resolve(context.Background(), spec, "")
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
}

// =============================================================================
// 6. MALICIOUS SOURCE / MAN-IN-THE-MIDDLE
//    Test behavior when the download source returns unexpected content.
// =============================================================================

func TestSecurity_SourceReturnsEmptyArchive(t *testing.T) {
	spec := BinarySpec{
		Name:         "test-binary",
		AssetPattern: "{name}-{os}-{arch}.tar.gz",
	}
	asset := assetName(spec)

	// Empty tar.gz (valid gzip, empty tar)
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())

	server := setupTestDownloadServer(t, map[string][]byte{
		"/v1.0.0/" + asset: buf.Bytes(),
	})
	spec.Source = &testSource{version: "v1.0.0", serverURL: server.URL}
	cfg := testConfig(t)

	_, err := cfg.resolve(context.Background(), spec, "")
	assert.Error(t, err, "empty archive should fail - binary not found")
	assert.Contains(t, err.Error(), "not found in archive")
}

func TestSecurity_SourceReturnsGarbageData(t *testing.T) {
	spec := BinarySpec{
		Name:         "test-binary",
		AssetPattern: "{name}-{os}-{arch}.tar.gz",
	}
	asset := assetName(spec)

	server := setupTestDownloadServer(t, map[string][]byte{
		"/v1.0.0/" + asset: []byte("THIS IS NOT A VALID ARCHIVE AT ALL"),
	})
	spec.Source = &testSource{version: "v1.0.0", serverURL: server.URL}
	cfg := testConfig(t)

	_, err := cfg.resolve(context.Background(), spec, "")
	assert.Error(t, err, "garbage data should fail extraction")
}

func TestSecurity_SourceReturnsHTMLInsteadOfBinary(t *testing.T) {
	spec := BinarySpec{
		Name:         "test-binary",
		AssetPattern: "{name}-{os}-{arch}.tar.gz",
	}
	asset := assetName(spec)

	// Simulates a captive portal or proxy returning HTML
	htmlContent := []byte("<html><body>Please authenticate</body></html>")
	server := setupTestDownloadServer(t, map[string][]byte{
		"/v1.0.0/" + asset: htmlContent,
	})
	spec.Source = &testSource{version: "v1.0.0", serverURL: server.URL}
	cfg := testConfig(t)

	_, err := cfg.resolve(context.Background(), spec, "")
	assert.Error(t, err, "HTML response should fail extraction")
}

// =============================================================================
// 7. ENV VAR INJECTION
//    Test that HCPCTL_CACHE_DIR cannot be used for path traversal.
// =============================================================================

func TestSecurity_EnvVarCacheDirTraversal(t *testing.T) {
	// Setting HCPCTL_CACHE_DIR to a path with traversal components
	// The env var is used as-is (filepath.Join normalizes), so this tests
	// whether the resolved path stays within expected bounds.
	cfg := &resolverConfig{}
	spec := BinarySpec{Name: "test-binary"}

	if runtime.GOOS == "windows" {
		t.Setenv("HCPCTL_CACHE_DIR", `C:\temp\..\..\..\Windows`)
		baseDir, err := cfg.cacheBaseDir(spec)
		require.NoError(t, err)
		assert.Equal(t, `C:\Windows\test-binary`, baseDir,
			"RISK: env var path traversal normalizes on Windows - user controls env")
	} else {
		t.Setenv("HCPCTL_CACHE_DIR", "/tmp/../../../etc")
		baseDir, err := cfg.cacheBaseDir(spec)
		require.NoError(t, err)
		assert.Equal(t, "/etc/test-binary", baseDir,
			"RISK: env var path traversal resolves to /etc/test-binary - "+
				"this is by design (user controls env), but document the risk")
	}
}

func TestSecurity_EnvVarCacheDirWithSpaces(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "path with spaces")
	t.Setenv("HCPCTL_CACHE_DIR", dir)

	cfg := &resolverConfig{}
	spec := BinarySpec{Name: "test-binary"}

	baseDir, err := cfg.cacheBaseDir(spec)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dir, "test-binary"), baseDir)
}

func TestSecurity_EnvVarCacheDirEmpty(t *testing.T) {
	t.Setenv("HCPCTL_CACHE_DIR", "")

	cfg := &resolverConfig{}
	spec := BinarySpec{Name: "test-binary"}

	baseDir, err := cfg.cacheBaseDir(spec)
	require.NoError(t, err)
	// Should fall through to os.UserCacheDir()
	assert.NotEmpty(t, baseDir)
	assert.True(t, strings.HasSuffix(baseDir, filepath.Join("hcpctl", "bin", "test-binary")))
}

// =============================================================================
// 8. BINARY NAME INJECTION
//    Test that BinarySpec.Name cannot be used for path traversal.
// =============================================================================

func TestSecurity_BinaryNameWithPathTraversal(t *testing.T) {
	// Validates that BinarySpec.Name with path traversal is rejected
	// by validateName() called from resolve().
	maliciousNames := []string{
		"../../../etc/cron.d/backdoor",
		"test-binary/../../escape",
		"test\x00binary",
	}

	for _, name := range maliciousNames {
		t.Run(name, func(t *testing.T) {
			cfg := testConfig(t)
			spec := BinarySpec{
				Name:         name,
				Source:       &testSource{version: "v1.0.0"},
				AssetPattern: "{name}-{os}-{arch}.tar.gz",
			}

			_, err := cfg.resolve(context.Background(), spec, "")
			assert.Error(t, err, "malicious binary name %q should be rejected", name)
			assert.Contains(t, err.Error(), "invalid binary name")
		})
	}
}

func TestSecurity_BinaryNameEmptyRejected(t *testing.T) {
	cfg := testConfig(t)
	spec := BinarySpec{
		Name:         "",
		Source:       &testSource{version: "v1.0.0"},
		AssetPattern: "{name}-{os}-{arch}.tar.gz",
	}

	_, err := cfg.resolve(context.Background(), spec, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must not be empty")
}

// =============================================================================
// 9. CACHE OVERWRITE SAFETY
//    Test that the always-download behavior safely overwrites existing binaries.
// =============================================================================

func TestSecurity_OverwritePreservesPermissions(t *testing.T) {
	binaryContent := []byte("#!/bin/sh\necho v1\n")
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

	info, err := os.Stat(result)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0755), info.Mode().Perm(),
		"binary should have 0755 permissions after first download")

	// Second download (overwrite)
	binaryContent2 := []byte("#!/bin/sh\necho v2\n")
	tarGzData2 := createTestTarGz(t, "test-binary", binaryContent2)
	server2 := setupTestDownloadServer(t, map[string][]byte{
		"/v2.0.0/" + asset: tarGzData2,
	})
	spec.Source = &testSource{version: "v2.0.0", serverURL: server2.URL}

	result2, err := cfg.resolve(context.Background(), spec, "")
	require.NoError(t, err)
	assert.Equal(t, result, result2)

	info2, err := os.Stat(result2)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0755), info2.Mode().Perm(),
		"binary should have 0755 permissions after overwrite")

	content, err := os.ReadFile(result2)
	require.NoError(t, err)
	assert.Equal(t, binaryContent2, content, "binary should contain v2 content after overwrite")
}

func TestSecurity_OverwriteReadOnlyBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permissions not enforced on Windows")
	}
	binaryContent := []byte("#!/bin/sh\necho v1\n")
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

	// Make the binary read-only
	require.NoError(t, os.Chmod(result, 0444))
	t.Cleanup(func() {
		if err := os.Chmod(result, 0755); err != nil {
			t.Logf("failed to restore permissions on %q: %v", result, err)
		}
	})

	// Attempt overwrite - O_TRUNC on a read-only file may fail
	binaryContent2 := []byte("#!/bin/sh\necho v2\n")
	tarGzData2 := createTestTarGz(t, "test-binary", binaryContent2)
	server2 := setupTestDownloadServer(t, map[string][]byte{
		"/v2.0.0/" + asset: tarGzData2,
	})
	spec.Source = &testSource{version: "v2.0.0", serverURL: server2.URL}

	_, err = cfg.resolve(context.Background(), spec, "")
	// This documents whether overwriting a read-only cached binary works.
	// If it fails, the error should be clear about permissions.
	if err != nil {
		assert.Contains(t, err.Error(), "permission denied",
			"error should mention permissions when overwriting read-only file")
	}
}

// =============================================================================
// 10. EXPLICIT PATH INJECTION
//     Test that the explicit binary path flag cannot be abused.
// =============================================================================

func TestSecurity_ExplicitPathToSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks require elevated privileges on Windows")
	}
	// Create a symlink to /dev/null
	symlinkPath := filepath.Join(t.TempDir(), "fake-binary")
	require.NoError(t, os.Symlink("/dev/null", symlinkPath))

	cfg := testConfig(t)
	spec := BinarySpec{Name: "test-binary"}

	// Explicit path follows symlinks - os.Stat resolves them
	result, err := cfg.resolve(context.Background(), spec, symlinkPath)
	require.NoError(t, err)
	assert.Equal(t, symlinkPath, result,
		"explicit path to symlink is accepted - user is responsible for this")
}

func TestSecurity_ExplicitPathToDirectory(t *testing.T) {
	dirPath := t.TempDir()

	cfg := testConfig(t)
	spec := BinarySpec{Name: "test-binary"}

	_, err := cfg.resolve(context.Background(), spec, dirPath)
	assert.Error(t, err, "explicit path pointing to a directory should be rejected")
	assert.Contains(t, err.Error(), "is a directory")
}

// =============================================================================
// 11. DOWNLOAD FAILURE CLEANUP
//     Verify partial downloads are cleaned up and don't leave
//     corrupt binaries that could be executed.
// =============================================================================

func TestSecurity_PartialDownloadCleanup(t *testing.T) {
	spec := BinarySpec{
		Name:         "test-binary",
		AssetPattern: "{name}-{os}-{arch}.tar.gz",
	}
	asset := assetName(spec)

	// Server sends partial data then closes connection
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if r.URL.Path == "/v1.0.0/"+asset {
			// Send partial gzip header but truncate
			_, err := w.Write([]byte{0x1f, 0x8b, 0x08, 0x00})
			require.NoError(t, err)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)

	spec.Source = &testSource{version: "v1.0.0", serverURL: server.URL}
	cfg := testConfig(t)

	_, err := cfg.resolve(context.Background(), spec, "")
	assert.Error(t, err, "partial download should fail")

	// Verify no corrupt binary was left in the cache
	binPath, pathErr := cfg.cachedBinaryPath(spec)
	require.NoError(t, pathErr)
	_, statErr := os.Stat(binPath)
	assert.True(t, os.IsNotExist(statErr),
		"corrupt binary should be cleaned up after failed download")
}

// =============================================================================
// 12. OFFLINE FALLBACK SAFETY
//     Test that the offline fallback doesn't serve a binary that was
//     planted by an attacker in the cache directory.
// =============================================================================

func TestSecurity_OfflineFallbackServesPlantedBinary(t *testing.T) {
	cfg := testConfig(t)
	spec := BinarySpec{
		Name:         "test-binary",
		Source:       &testSource{versionErr: fmt.Errorf("network down")},
		AssetPattern: "{name}-{os}-{arch}.tar.gz",
	}

	// Plant a malicious binary in the cache
	baseDir, err := cfg.cacheBaseDir(spec)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(baseDir, 0755))

	maliciousContent := []byte("#!/bin/sh\nrm -rf /\n")
	plantedPath := filepath.Join(baseDir, "test-binary")
	require.NoError(t, os.WriteFile(plantedPath, maliciousContent, 0755))

	// When offline, the resolver falls back to the planted binary
	result, err := cfg.resolve(context.Background(), spec, "")
	require.NoError(t, err)
	assert.Equal(t, plantedPath, result,
		"RISK DOCUMENTATION: offline fallback will serve any binary found in cache, "+
			"including planted ones. Cache directory permissions are the only defense.")
}

// =============================================================================
// 13. CONCURRENT RESOLVE WITH DIFFERENT CACHE DIRS
//     Since cacheDir is now a parameter (not global state), concurrent calls
//     with different cache dirs are naturally isolated.
// =============================================================================

func TestSecurity_ConcurrentResolveIsolatedCacheDirs(t *testing.T) {
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

	var wg sync.WaitGroup
	const goroutines = 10
	results := make([]string, goroutines)
	errs := make([]error, goroutines)
	cacheDirs := make([]string, goroutines)

	for i := range goroutines {
		cacheDirs[i] = t.TempDir()
	}

	wg.Add(goroutines)
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			results[idx], errs[idx] = Resolve(context.Background(), spec, "", cacheDirs[idx])
		}(i)
	}
	wg.Wait()

	for i := range goroutines {
		assert.NoError(t, errs[i], "goroutine %d failed", i)
		assert.True(t, strings.HasPrefix(results[i], cacheDirs[i]),
			"goroutine %d: binary should be in its own cache dir", i)
	}

	// Each goroutine should have its own independent binary
	for i := 1; i < goroutines; i++ {
		assert.NotEqual(t, results[0], results[i],
			"goroutine %d should have different path from goroutine 0", i)
	}
}

// =============================================================================
// 14. LARGE TAR ENTRY HEADERS (DECOMPRESSION BOMB)
//     Test that a tar entry claiming to be enormous is bounded.
// =============================================================================

func TestSecurity_WriterExtractedBinaryRespectsMaxSize(t *testing.T) {
	// Verify that writeExtractedBinary enforces the maxBinarySize limit.
	// We can't easily create a tar with mismatched header size, so test
	// writeExtractedBinary directly with a reader that produces data
	// beyond the limit.

	// Create a reader that produces maxBinarySize + 100 bytes
	overSize := maxBinarySize + 100
	bigReader := strings.NewReader(strings.Repeat("A", int(overSize)))

	destPath := filepath.Join(t.TempDir(), "test-binary")
	err := writeExtractedBinary(bigReader, "test-binary", destPath)
	assert.Error(t, err, "should reject binary exceeding maxBinarySize")
	assert.Contains(t, err.Error(), "exceeds maximum allowed size")

	// Verify the oversized binary was cleaned up
	_, statErr := os.Stat(destPath)
	assert.True(t, os.IsNotExist(statErr),
		"oversized binary should be removed after rejection")
}

// =============================================================================
// 15. DOWNLOAD URL INJECTION
//     Test that version strings containing URL-special characters
//     don't cause unexpected HTTP behavior.
// =============================================================================

func TestSecurity_VersionWithURLSpecialChars(t *testing.T) {
	specialVersions := []string{
		"v1.0.0?malicious=true",
		"v1.0.0#fragment",
		"v1.0.0 space",
		"v1.0.0\nnewline",
		"v1.0.0\rcarriage",
	}

	for _, version := range specialVersions {
		t.Run(fmt.Sprintf("version=%q", version), func(t *testing.T) {
			cfg := testConfig(t)
			spec := BinarySpec{
				Name:         "test-binary",
				Source:       &testSource{version: version},
				AssetPattern: "{name}-{os}-{arch}.tar.gz",
			}

			_, err := cfg.resolve(context.Background(), spec, "")
			assert.Error(t, err, "version %q should be rejected", version)
			assert.Contains(t, err.Error(), "invalid version string")
		})
	}
}

// =============================================================================
// 16. TAR WITH MULTIPLE MATCHING ENTRIES
//     Test that only the first matching binary is extracted.
// =============================================================================

func TestSecurity_TarWithDuplicateEntries(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	// First entry - legitimate
	content1 := []byte("#!/bin/sh\necho legitimate\n")
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name: "test-binary",
		Mode: 0755,
		Size: int64(len(content1)),
	}))
	_, err := tw.Write(content1)
	require.NoError(t, err)

	// Second entry - same name, malicious content
	content2 := []byte("#!/bin/sh\necho PWNED\n")
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name: "test-binary",
		Mode: 0755,
		Size: int64(len(content2)),
	}))
	_, err = tw.Write(content2)
	require.NoError(t, err)

	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())

	archivePath := filepath.Join(t.TempDir(), "duplicate.tar.gz")
	require.NoError(t, os.WriteFile(archivePath, buf.Bytes(), 0644))

	destPath := filepath.Join(t.TempDir(), "test-binary")
	err = extractTarGz(archivePath, "test-binary", destPath)
	require.NoError(t, err)

	// Should get the FIRST matching entry
	extracted, err := os.ReadFile(destPath)
	require.NoError(t, err)
	assert.Equal(t, content1, extracted,
		"should extract only the first matching entry, not the second")
}

// =============================================================================
// 17. WRITE TO NON-WRITABLE CACHE DIRECTORY
//     Test behavior when cache directory exists but is not writable.
// =============================================================================

func TestSecurity_NonWritableCacheDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permissions not enforced on Windows")
	}
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
	baseDir, err := cfg.cacheBaseDir(spec)
	require.NoError(t, err)

	// Create the directory, then make it read-only
	require.NoError(t, os.MkdirAll(baseDir, 0755))
	require.NoError(t, os.Chmod(baseDir, 0555))
	t.Cleanup(func() {
		if err := os.Chmod(baseDir, 0755); err != nil {
			t.Logf("failed to restore permissions on %q: %v", baseDir, err)
		}
	})

	_, err = cfg.resolve(context.Background(), spec, "")
	assert.Error(t, err, "should fail when cache directory is not writable")
}

// =============================================================================
// 18. CONTEXT CANCELLATION DURING DOWNLOAD
//     Test that cancelling context during download cleans up properly.
// =============================================================================

func TestSecurity_ContextCancellationDuringDownload(t *testing.T) {
	spec := BinarySpec{
		Name:         "test-binary",
		AssetPattern: "{name}-{os}-{arch}.tar.gz",
	}
	asset := assetName(spec)

	downloadStarted := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1.0.0/"+asset {
			close(downloadStarted)
			// Block forever to simulate slow download
			<-r.Context().Done()
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)

	spec.Source = &testSource{version: "v1.0.0", serverURL: server.URL}
	cfg := testConfig(t)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		_, err := cfg.resolve(ctx, spec, "")
		done <- err
	}()

	// Wait for download to start, then cancel
	<-downloadStarted
	cancel()

	err := <-done
	assert.Error(t, err, "should fail when context is cancelled")

	// Verify no partial binary was left
	binPath, pathErr := cfg.cachedBinaryPath(spec)
	require.NoError(t, pathErr)
	_, statErr := os.Stat(binPath)
	assert.True(t, os.IsNotExist(statErr),
		"no partial binary should remain after context cancellation")
}

// =============================================================================
// 19. ALWAYS-DOWNLOAD: EXISTING BINARY REPLACED WITH MALICIOUS ONE
//     Since we always download (no cache-hit shortcut), verify that a
//     previously-good cached binary gets replaced by whatever the source
//     serves. If a source is compromised, the next resolve overwrites
//     the legitimate binary.
// =============================================================================

func TestSecurity_CompromisedSourceReplacesGoodBinary(t *testing.T) {
	legitimateContent := []byte("#!/bin/sh\necho legitimate\n")
	maliciousContent := []byte("#!/bin/sh\nrm -rf /\n")

	spec := BinarySpec{
		Name:         "test-binary",
		AssetPattern: "{name}-{os}-{arch}.tar.gz",
	}
	asset := assetName(spec)

	// First download: legitimate binary
	tarGz1 := createTestTarGz(t, "test-binary", legitimateContent)
	server1 := setupTestDownloadServer(t, map[string][]byte{
		"/v1.0.0/" + asset: tarGz1,
	})
	spec.Source = &testSource{version: "v1.0.0", serverURL: server1.URL}
	cfg := testConfig(t)

	result1, err := cfg.resolve(context.Background(), spec, "")
	require.NoError(t, err)
	content1, _ := os.ReadFile(result1)
	assert.Equal(t, legitimateContent, content1)

	// Second download: compromised source serves malicious binary
	tarGz2 := createTestTarGz(t, "test-binary", maliciousContent)
	server2 := setupTestDownloadServer(t, map[string][]byte{
		"/v2.0.0/" + asset: tarGz2,
	})
	spec.Source = &testSource{version: "v2.0.0", serverURL: server2.URL}

	result2, err := cfg.resolve(context.Background(), spec, "")
	require.NoError(t, err)

	// The legitimate binary is now replaced with the malicious one.
	// This is the expected behavior (always-download overwrites),
	// but documents the risk: a compromised source = compromised binary.
	content2, _ := os.ReadFile(result2)
	assert.Equal(t, maliciousContent, content2,
		"RISK DOCUMENTATION: compromised source overwrites previously-legitimate "+
			"cached binary. Checksum verification (when configured) is the only defense.")
}

// =============================================================================
// 20. ALWAYS-DOWNLOAD: FAILED DOWNLOAD DESTROYS EXISTING GOOD BINARY
//     If the source is reachable (LatestTagName succeeds) but the download
//     fails, verify the old binary is cleaned up and not left behind
//     in a potentially inconsistent state.
// =============================================================================

func TestSecurity_FailedDownloadPreservesExistingBinary(t *testing.T) {
	legitimateContent := []byte("#!/bin/sh\necho good\n")

	spec := BinarySpec{
		Name:         "test-binary",
		AssetPattern: "{name}-{os}-{arch}.tar.gz",
	}
	asset := assetName(spec)

	// First: successful download
	tarGz := createTestTarGz(t, "test-binary", legitimateContent)
	server := setupTestDownloadServer(t, map[string][]byte{
		"/v1.0.0/" + asset: tarGz,
	})
	spec.Source = &testSource{version: "v1.0.0", serverURL: server.URL}
	cfg := testConfig(t)

	result, err := cfg.resolve(context.Background(), spec, "")
	require.NoError(t, err)

	// Confirm good binary exists
	_, err = os.Stat(result)
	require.NoError(t, err)

	// Second: source says v2.0.0 exists but download 404s
	server2 := setupTestDownloadServer(t, map[string][]byte{})
	spec.Source = &testSource{version: "v2.0.0", serverURL: server2.URL}

	_, err = cfg.resolve(context.Background(), spec, "")
	assert.Error(t, err, "download should fail")

	// The old binary should be preserved (atomic extract-then-rename)
	content, err := os.ReadFile(result)
	require.NoError(t, err)
	assert.Equal(t, legitimateContent, content,
		"previously-good cached binary should survive a failed download")
}

// =============================================================================
// 21. CHECKSUM BYPASS: SOURCE THAT FAILS CHECKSUM DOWNLOAD
//     When ChecksumAsset is configured but the checksum file download fails,
//     verification is SKIPPED (returns nil). A MITM could block the checksum
//     download to bypass verification.
// =============================================================================

func TestSecurity_ChecksumDownloadFailureBypass(t *testing.T) {
	maliciousContent := []byte("#!/bin/sh\necho evil\n")
	maliciousTarGz := createTestTarGz(t, "test-binary", maliciousContent)

	spec := BinarySpec{
		Name:          "test-binary",
		AssetPattern:  "{name}-{os}-{arch}.tar.gz",
		ChecksumAsset: "SHA256_SUM",
	}
	asset := assetName(spec)

	// Serve the binary but NOT the checksum file (404)
	server := setupTestDownloadServer(t, map[string][]byte{
		"/v1.0.0/" + asset: maliciousTarGz,
		// SHA256_SUM intentionally missing
	})
	spec.Source = &testSource{version: "v1.0.0", serverURL: server.URL}
	cfg := testConfig(t)

	// Checksum download failure now causes download to fail entirely,
	// preventing a MITM from bypassing verification by blocking the checksum file.
	_, err := cfg.resolve(context.Background(), spec, "")
	assert.Error(t, err, "download should fail when checksum file is unavailable")
	assert.Contains(t, err.Error(), "checksum verification failed")
}

// =============================================================================
// 22. SYMLINK REPLACEMENT ATTACK (TOCTOU)
//     Between cachedBinaryPath() computing the path and download() writing
//     to it, an attacker could replace the parent directory with a symlink.
// =============================================================================

func TestSecurity_SymlinkReplacementBetweenPathAndWrite(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks require elevated privileges on Windows")
	}
	binaryContent := []byte("#!/bin/sh\necho hello\n")
	tarGzData := createTestTarGz(t, "test-binary", binaryContent)

	spec := BinarySpec{
		Name:         "test-binary",
		AssetPattern: "{name}-{os}-{arch}.tar.gz",
	}
	asset := assetName(spec)

	escapeTarget := t.TempDir()

	// Server that replaces the cache dir with a symlink during download
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1.0.0/"+asset {
			// Write the valid archive data
			_, err := w.Write(tarGzData)
			require.NoError(t, err)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)

	spec.Source = &testSource{version: "v1.0.0", serverURL: server.URL}
	cfg := testConfig(t)

	// Pre-create the cache directory
	baseDir, err := cfg.cacheBaseDir(spec)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(baseDir, 0755))

	// Replace the cache dir with a symlink to our escape target
	require.NoError(t, os.RemoveAll(baseDir))
	require.NoError(t, os.Symlink(escapeTarget, baseDir))

	result, err := cfg.resolve(context.Background(), spec, "")
	if err != nil {
		// If it fails, that's acceptable defense
		return
	}

	// The binary was written through the symlink to the escape target.
	// This is expected — the resolver follows symlinks in the cache path.
	realPath, _ := filepath.EvalSymlinks(result)
	realEscapeTarget, _ := filepath.EvalSymlinks(escapeTarget)
	assert.True(t, strings.HasPrefix(realPath, realEscapeTarget),
		"binary should be written through symlink to escape target")
	t.Logf("RISK DOCUMENTATION: symlink in cache directory redirects binary writes to %q. "+
		"Cache directory permissions are the only defense against local attackers.", realPath)
}

// =============================================================================
// 24. ASSET PATTERN INJECTION
//     Test that AssetPattern with path traversal doesn't cause issues.
// =============================================================================

func TestSecurity_AssetPatternWithTraversal(t *testing.T) {
	spec := BinarySpec{
		Name:         "test-binary",
		AssetPattern: "../../{name}-{os}-{arch}.tar.gz",
	}

	asset := assetName(spec)
	// The asset name is used in the download URL and as suffix check,
	// verify it doesn't cause local path issues
	assert.Contains(t, asset, "../../",
		"asset pattern traversal flows into download URL path")

	// Create a valid archive
	binaryContent := []byte("#!/bin/sh\necho hello\n")
	tarGzData := createTestTarGz(t, "test-binary", binaryContent)

	server := setupTestDownloadServer(t, map[string][]byte{
		"/v1.0.0/" + asset: tarGzData,
	})
	spec.Source = &testSource{version: "v1.0.0", serverURL: server.URL}
	cfg := testConfig(t)

	// Should still work (asset name only affects download URL, not local paths)
	result, err := cfg.resolve(context.Background(), spec, "")
	require.NoError(t, err)

	// Verify binary is in the expected cache location, not escaped
	absCache, _ := filepath.Abs(cfg.cacheRoot)
	absResult, _ := filepath.Abs(result)
	assert.True(t, strings.HasPrefix(absResult, absCache),
		"binary should be within cache root regardless of asset pattern")
}

// =============================================================================
// 25. OVERWRITE RUNNING BINARY
//     If the cached binary is currently being executed, the overwrite
//     behavior could cause issues on some OSes.
// =============================================================================

func TestSecurity_OverwriteWhileBinaryCouldBeRunning(t *testing.T) {
	binaryContent := []byte("#!/bin/sh\nsleep 1\n")
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

	// Make the binary executable and verify it exists
	info, err := os.Stat(result)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0755), info.Mode().Perm())

	// Second download immediately overwrites via O_TRUNC
	// On Unix, this is safe (existing file descriptors/running processes
	// keep the old inode). On Windows it could fail with EBUSY.
	newContent := []byte("#!/bin/sh\necho replaced\n")
	tarGzData2 := createTestTarGz(t, "test-binary", newContent)
	server2 := setupTestDownloadServer(t, map[string][]byte{
		"/v2.0.0/" + asset: tarGzData2,
	})
	spec.Source = &testSource{version: "v2.0.0", serverURL: server2.URL}

	result2, err := cfg.resolve(context.Background(), spec, "")
	require.NoError(t, err)
	assert.Equal(t, result, result2, "should overwrite same path")

	content, _ := os.ReadFile(result2)
	assert.Equal(t, newContent, content)
}

// =============================================================================
// 26. EMPTY BINARY IN ARCHIVE
//     Test that an archive containing a zero-byte binary is handled.
// =============================================================================

func TestSecurity_EmptyBinaryInArchive(t *testing.T) {
	emptyTarGz := createTestTarGz(t, "test-binary", []byte{})

	spec := BinarySpec{
		Name:         "test-binary",
		AssetPattern: "{name}-{os}-{arch}.tar.gz",
	}
	asset := assetName(spec)

	server := setupTestDownloadServer(t, map[string][]byte{
		"/v1.0.0/" + asset: emptyTarGz,
	})
	spec.Source = &testSource{version: "v1.0.0", serverURL: server.URL}
	cfg := testConfig(t)

	// A zero-byte binary is technically valid (just useless)
	result, err := cfg.resolve(context.Background(), spec, "")
	if err != nil {
		return // rejecting empty binaries is acceptable
	}

	info, statErr := os.Stat(result)
	require.NoError(t, statErr)
	assert.Equal(t, int64(0), info.Size(),
		"RISK DOCUMENTATION: zero-byte binary is accepted and cached. "+
			"Executing it will fail but no early validation prevents caching.")
}

// =============================================================================
// 27. MALICIOUS CHECKSUM WITH HASH OF DIFFERENT ASSET
//     Test that the checksum parser matches the correct asset filename.
// =============================================================================

func TestSecurity_ChecksumForWrongAssetAccepted(t *testing.T) {
	maliciousContent := []byte("#!/bin/sh\necho evil\n")
	maliciousTarGz := createTestTarGz(t, "test-binary", maliciousContent)
	maliciousHash := fmt.Sprintf("%x", sha256.Sum256(maliciousTarGz))

	// A different, legitimate binary
	legitimateContent := []byte("#!/bin/sh\necho good\n")
	legitimateTarGz := createTestTarGz(t, "test-binary", legitimateContent)
	legitimateHash := fmt.Sprintf("%x", sha256.Sum256(legitimateTarGz))

	spec := BinarySpec{
		Name:          "test-binary",
		AssetPattern:  "{name}-{os}-{arch}.tar.gz",
		ChecksumAsset: "SHA256_SUM",
	}
	asset := assetName(spec)

	// Checksum file has hash for a DIFFERENT asset name, plus the correct
	// hash for our actual asset
	checksumContent := fmt.Sprintf(
		"%s  other-binary-linux-amd64.tar.gz\n%s  %s\n",
		legitimateHash, maliciousHash, asset,
	)

	server := setupTestDownloadServer(t, map[string][]byte{
		"/v1.0.0/" + asset:   maliciousTarGz,
		"/v1.0.0/SHA256_SUM": []byte(checksumContent),
	})
	spec.Source = &testSource{version: "v1.0.0", serverURL: server.URL}
	cfg := testConfig(t)

	// The checksum matches the malicious binary (attacker controls both
	// the binary AND the checksum file). This is expected — checksum
	// verification only protects against transport-level tampering,
	// not a fully compromised source.
	result, err := cfg.resolve(context.Background(), spec, "")
	assert.NoError(t, err)

	content, _ := os.ReadFile(result)
	assert.Equal(t, maliciousContent, content,
		"RISK DOCUMENTATION: if attacker controls both binary and checksum file, "+
			"verification passes. Checksums protect transit, not source compromise.")
}

// =============================================================================
// 28. VALIDATE NAME EDGE CASES
//     Test boundary cases in the name validation function.
// =============================================================================

func TestSecurity_ValidateNameEdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantValid bool
	}{
		{name: "simple hyphenated name", input: "must-gather-clean", wantValid: true},
		{name: "underscore in name", input: "binary_v2", wantValid: true},
		{name: "single dot is allowed", input: "my.tool", wantValid: true},
		{name: "single character name", input: "a", wantValid: true},
		{name: "leading single dot is allowed", input: ".hidden", wantValid: true},
		{name: "version-like name", input: "tool-1.0", wantValid: true},
		{name: "bare double-dot path component", input: "..", wantValid: false},
		{name: "double-dot prefix in local filename", input: "..hidden", wantValid: true},
		{name: "double-dot suffix in local filename", input: "name..", wantValid: true},
		{name: "double-dot inside local filename", input: "na..me", wantValid: true},
		{name: "forward slash separator", input: "a/b", wantValid: false},
		{name: "backslash separator", input: "a\\b", wantValid: false},
		{name: "empty name", input: "", wantValid: false},
		{name: "null byte in name", input: "a\x00b", wantValid: false},
		{name: "current directory reference", input: ".", wantValid: false},
		{name: "bare forward slash", input: "/", wantValid: false},
		{name: "bare backslash", input: "\\", wantValid: false},
		{name: "classic path traversal", input: "../escape", wantValid: false},
		{name: "nested traversal with valid prefix", input: "name/../../escape", wantValid: false},
		{name: "long but valid name", input: strings.Repeat("a", 255), wantValid: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateName(tc.input)
			if tc.wantValid {
				assert.NoError(t, err, "name %q should be valid", tc.input)
			} else {
				assert.Error(t, err, "name %q should be invalid", tc.input)
			}
		})
	}
}

// =============================================================================
// 29. MULTIPLE CONCURRENT DOWNLOADS WITH DIFFERENT VERSIONS
//     When source changes version between concurrent resolve calls,
//     verify no corruption occurs.
// =============================================================================

func TestSecurity_ConcurrentResolveDifferentVersions(t *testing.T) {
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

	var wg sync.WaitGroup
	wg.Add(2)

	var err1, err2 error
	var result1, result2 string

	go func() {
		defer wg.Done()
		s := spec
		s.Source = &testSource{version: "v1.0.0", serverURL: server.URL}
		result1, err1 = cfg.resolve(context.Background(), s, "")
	}()

	go func() {
		defer wg.Done()
		s := spec
		s.Source = &testSource{version: "v2.0.0", serverURL: server.URL}
		result2, err2 = cfg.resolve(context.Background(), s, "")
	}()

	wg.Wait()

	assert.NoError(t, err1)
	assert.NoError(t, err2)

	// Both resolve to the same path (flat cache, no version subdir)
	assert.Equal(t, result1, result2, "both should resolve to same cache path")

	// The final content could be either v1 or v2 depending on timing,
	// but it MUST be one of them — never corrupted/mixed
	finalContent, err := os.ReadFile(result1)
	require.NoError(t, err)
	assert.True(t,
		bytes.Equal(finalContent, content1) || bytes.Equal(finalContent, content2),
		"final binary must be one complete version, not corrupted: got %q", finalContent)
}

// =============================================================================
// 30. TAR WITH SYMLINK ENTRY POINTING OUTSIDE
//     A tar containing a symlink entry should not be followed during
//     extraction.
// =============================================================================

func TestSecurity_TarWithSymlinkEntry(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	// Add a symlink entry pointing outside
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name:     "test-binary",
		Typeflag: tar.TypeSymlink,
		Linkname: "/etc/passwd",
		Mode:     0755,
	}))

	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())

	archivePath := filepath.Join(t.TempDir(), "symlink.tar.gz")
	require.NoError(t, os.WriteFile(archivePath, buf.Bytes(), 0644))

	destPath := filepath.Join(t.TempDir(), "test-binary")
	err := extractTarGz(archivePath, "test-binary", destPath)

	// extractTarGz checks header.Typeflag == tar.TypeReg, so symlink
	// entries are skipped. The binary should NOT be found.
	assert.Error(t, err, "symlink entry in tar should not be extracted as a binary")
	assert.Contains(t, err.Error(), "not found in archive")

	// Verify nothing was created at dest
	_, statErr := os.Stat(destPath)
	assert.True(t, os.IsNotExist(statErr),
		"no file should be created for symlink tar entries")
}

// =============================================================================
// 31. CHECKSUM BYPASS VIA OVERSIZED CHECKSUM FILE
//     An attacker serving a >1MB checksum file must not bypass verification.
// =============================================================================

func TestSecurity_OversizedChecksumFileRejectsDownload(t *testing.T) {
	binaryContent := []byte("#!/bin/sh\necho evil\n")
	tarGzData := createTestTarGz(t, "test-binary", binaryContent)

	spec := BinarySpec{
		Name:          "test-binary",
		AssetPattern:  "{name}-{os}-{arch}.tar.gz",
		ChecksumAsset: "SHA256_SUM",
	}
	asset := assetName(spec)

	// Serve a checksum file that exceeds maxChecksumFileSize
	oversizedChecksum := strings.Repeat("a", maxChecksumFileSize+1)
	server := setupTestDownloadServer(t, map[string][]byte{
		"/v1.0.0/" + asset:   tarGzData,
		"/v1.0.0/SHA256_SUM": []byte(oversizedChecksum),
	})
	spec.Source = &testSource{version: "v1.0.0", serverURL: server.URL}
	cfg := testConfig(t)

	_, err := cfg.resolve(context.Background(), spec, "")
	assert.Error(t, err, "oversized checksum file must reject the download, not silently skip verification")
	assert.Contains(t, err.Error(), "exceeds maximum allowed size")

	// Verify no binary was cached
	binPath, pathErr := cfg.cachedBinaryPath(spec)
	require.NoError(t, pathErr)
	_, statErr := os.Stat(binPath)
	assert.True(t, os.IsNotExist(statErr),
		"no binary should be cached when checksum verification fails")
}

// =============================================================================
// 32. CHECKSUM BYPASS VIA INVALID HASH IN CHECKSUM FILE
//     A checksum file with a malformed hash for our asset must not bypass
//     verification.
// =============================================================================

func TestSecurity_InvalidHashLengthRejectsDownload(t *testing.T) {
	binaryContent := []byte("#!/bin/sh\necho evil\n")
	tarGzData := createTestTarGz(t, "test-binary", binaryContent)

	spec := BinarySpec{
		Name:          "test-binary",
		AssetPattern:  "{name}-{os}-{arch}.tar.gz",
		ChecksumAsset: "SHA256_SUM",
	}
	asset := assetName(spec)

	// Hash that's too short (32 chars instead of 64)
	shortHash := "abcdef1234567890abcdef1234567890"
	checksumContent := fmt.Sprintf("%s  %s\n", shortHash, asset)
	server := setupTestDownloadServer(t, map[string][]byte{
		"/v1.0.0/" + asset:   tarGzData,
		"/v1.0.0/SHA256_SUM": []byte(checksumContent),
	})
	spec.Source = &testSource{version: "v1.0.0", serverURL: server.URL}
	cfg := testConfig(t)

	_, err := cfg.resolve(context.Background(), spec, "")
	assert.Error(t, err, "invalid hash length must reject the download")
	assert.Contains(t, err.Error(), "expected 64")
}

func TestSecurity_NonHexHashRejectsDownload(t *testing.T) {
	binaryContent := []byte("#!/bin/sh\necho evil\n")
	tarGzData := createTestTarGz(t, "test-binary", binaryContent)

	spec := BinarySpec{
		Name:          "test-binary",
		AssetPattern:  "{name}-{os}-{arch}.tar.gz",
		ChecksumAsset: "SHA256_SUM",
	}
	asset := assetName(spec)

	// 64-char string that isn't valid hex
	notHex := "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
	checksumContent := fmt.Sprintf("%s  %s\n", notHex, asset)
	server := setupTestDownloadServer(t, map[string][]byte{
		"/v1.0.0/" + asset:   tarGzData,
		"/v1.0.0/SHA256_SUM": []byte(checksumContent),
	})
	spec.Source = &testSource{version: "v1.0.0", serverURL: server.URL}
	cfg := testConfig(t)

	_, err := cfg.resolve(context.Background(), spec, "")
	assert.Error(t, err, "non-hex hash must reject the download")
	assert.Contains(t, err.Error(), "not valid hex")
}

// =============================================================================
// 33. CHECKSUM BYPASS VIA MISSING ASSET ENTRY
//     A checksum file that doesn't contain our asset must not bypass
//     verification.
// =============================================================================

func TestSecurity_AssetMissingFromChecksumFileRejectsDownload(t *testing.T) {
	binaryContent := []byte("#!/bin/sh\necho evil\n")
	tarGzData := createTestTarGz(t, "test-binary", binaryContent)

	spec := BinarySpec{
		Name:          "test-binary",
		AssetPattern:  "{name}-{os}-{arch}.tar.gz",
		ChecksumAsset: "SHA256_SUM",
	}
	asset := assetName(spec)

	// Checksum file contains entries for OTHER assets but not ours
	checksumContent := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  other-binary-linux-amd64.tar.gz\n"
	server := setupTestDownloadServer(t, map[string][]byte{
		"/v1.0.0/" + asset:   tarGzData,
		"/v1.0.0/SHA256_SUM": []byte(checksumContent),
	})
	spec.Source = &testSource{version: "v1.0.0", serverURL: server.URL}
	cfg := testConfig(t)

	_, err := cfg.resolve(context.Background(), spec, "")
	assert.Error(t, err, "missing asset entry in checksum file must reject the download")
	assert.Contains(t, err.Error(), "not found in checksum file")
}

func TestSecurity_EmptyChecksumFileRejectsDownload(t *testing.T) {
	binaryContent := []byte("#!/bin/sh\necho evil\n")
	tarGzData := createTestTarGz(t, "test-binary", binaryContent)

	spec := BinarySpec{
		Name:          "test-binary",
		AssetPattern:  "{name}-{os}-{arch}.tar.gz",
		ChecksumAsset: "SHA256_SUM",
	}
	asset := assetName(spec)

	// Serve a completely empty checksum file
	server := setupTestDownloadServer(t, map[string][]byte{
		"/v1.0.0/" + asset:   tarGzData,
		"/v1.0.0/SHA256_SUM": []byte(""),
	})
	spec.Source = &testSource{version: "v1.0.0", serverURL: server.URL}
	cfg := testConfig(t)

	_, err := cfg.resolve(context.Background(), spec, "")
	assert.Error(t, err, "empty checksum file must reject the download")
	assert.Contains(t, err.Error(), "not found in checksum file")
}

// =============================================================================
// 34. EXPLICIT PATH TO SPECIAL FILES
//     Verify behavior with device files, FIFOs, etc.
// =============================================================================

func TestSecurity_ExplicitPathToDevNull(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("/dev/null does not exist on Windows")
	}
	cfg := testConfig(t)
	spec := BinarySpec{Name: "test-binary"}

	// /dev/null is a character device, not a regular file or directory.
	// os.Stat succeeds and IsDir() returns false, so the resolver accepts it.
	result, err := cfg.resolve(context.Background(), spec, "/dev/null")
	require.NoError(t, err)
	assert.Equal(t, "/dev/null", result,
		"explicit path to /dev/null is accepted - user is responsible for providing a valid binary")
}

func TestSecurity_ExplicitPathToNonexistent(t *testing.T) {
	cfg := testConfig(t)
	spec := BinarySpec{Name: "test-binary"}

	_, err := cfg.resolve(context.Background(), spec, "/nonexistent/path/binary")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to find binary")
}

// =============================================================================
// 35. CONCURRENT RESOLVE WITH PARAMETER ISOLATION
//     Verify that concurrent Resolve calls with different cacheDir params
//     don't interfere with each other, even during slow downloads.
// =============================================================================

func TestSecurity_ConcurrentResolveParameterIsolation(t *testing.T) {
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

	dir1 := t.TempDir()
	dir2 := t.TempDir()

	var wg sync.WaitGroup
	wg.Add(2)

	var result1, result2 string
	var err1, err2 error

	go func() {
		defer wg.Done()
		s := spec
		s.Source = &testSource{version: "v1.0.0", serverURL: server.URL}
		result1, err1 = Resolve(context.Background(), s, "", dir1)
	}()

	go func() {
		defer wg.Done()
		s := spec
		s.Source = &testSource{version: "v2.0.0", serverURL: server.URL}
		result2, err2 = Resolve(context.Background(), s, "", dir2)
	}()

	wg.Wait()

	require.NoError(t, err1)
	require.NoError(t, err2)

	// Each should be in its own cache dir
	assert.True(t, strings.HasPrefix(result1, dir1))
	assert.True(t, strings.HasPrefix(result2, dir2))

	// Each should have the correct content
	c1, _ := os.ReadFile(result1)
	c2, _ := os.ReadFile(result2)
	assert.Equal(t, content1, c1)
	assert.Equal(t, content2, c2)
}

// =============================================================================
// 36. CHECKSUM FILE WITH ONLY WHITESPACE/EMPTY LINES
//     Verify that a checksum file containing only whitespace is handled.
// =============================================================================

func TestSecurity_ChecksumFileOnlyWhitespace(t *testing.T) {
	binaryContent := []byte("#!/bin/sh\necho hello\n")
	tarGzData := createTestTarGz(t, "test-binary", binaryContent)

	spec := BinarySpec{
		Name:          "test-binary",
		AssetPattern:  "{name}-{os}-{arch}.tar.gz",
		ChecksumAsset: "SHA256_SUM",
	}
	asset := assetName(spec)

	checksumContent := "\n\n   \n\t\n\n"
	server := setupTestDownloadServer(t, map[string][]byte{
		"/v1.0.0/" + asset:   tarGzData,
		"/v1.0.0/SHA256_SUM": []byte(checksumContent),
	})
	spec.Source = &testSource{version: "v1.0.0", serverURL: server.URL}
	cfg := testConfig(t)

	_, err := cfg.resolve(context.Background(), spec, "")
	assert.Error(t, err, "whitespace-only checksum file must reject the download")
	assert.Contains(t, err.Error(), "not found in checksum file")
}

// =============================================================================
// 37. CACHE DIR WITH NO WRITE PERMISSION ON PARENT
//     Verify clear error when cache directory can't be created.
// =============================================================================

func TestSecurity_CacheDirParentNotWritable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permissions not enforced on Windows")
	}
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

	// Create a read-only parent directory
	parentDir := filepath.Join(t.TempDir(), "readonly-parent")
	require.NoError(t, os.MkdirAll(parentDir, 0755))
	require.NoError(t, os.Chmod(parentDir, 0555))
	t.Cleanup(func() {
		if err := os.Chmod(parentDir, 0755); err != nil {
			t.Logf("failed to restore permissions on %q: %v", parentDir, err)
		}
	})

	cfg := &resolverConfig{cacheRoot: filepath.Join(parentDir, "cache")}

	_, err := cfg.resolve(context.Background(), spec, "")
	assert.Error(t, err, "should fail when cache directory parent is not writable")
}

// =============================================================================
// 38. VERSION FILE NOT WRITTEN ON FAILED DOWNLOAD
//     Verify .version file is not created when download/checksum fails.
// =============================================================================

func TestSecurity_VersionFileNotWrittenOnFailedDownload(t *testing.T) {
	legitimateContent := []byte("#!/bin/sh\necho good\n")
	legitimateTarGz := createTestTarGz(t, "test-binary", legitimateContent)
	correctHash := fmt.Sprintf("%x", sha256.Sum256(legitimateTarGz))

	tamperedContent := []byte("#!/bin/sh\necho evil\n")
	tamperedTarGz := createTestTarGz(t, "test-binary", tamperedContent)

	spec := BinarySpec{
		Name:          "test-binary",
		AssetPattern:  "{name}-{os}-{arch}.tar.gz",
		ChecksumAsset: "SHA256_SUM",
	}
	asset := assetName(spec)

	// Serve tampered binary with legitimate checksum
	checksumContent := fmt.Sprintf("%s  %s\n", correctHash, asset)
	server := setupTestDownloadServer(t, map[string][]byte{
		"/v1.0.0/" + asset:   tamperedTarGz,
		"/v1.0.0/SHA256_SUM": []byte(checksumContent),
	})
	spec.Source = &testSource{version: "v1.0.0", serverURL: server.URL}
	cfg := testConfig(t)

	_, err := cfg.resolve(context.Background(), spec, "")
	assert.Error(t, err, "checksum mismatch should fail")

	// Verify no .version file was written
	versionPath, _ := cfg.cachedVersionPath(spec)
	_, statErr := os.Stat(versionPath)
	assert.True(t, os.IsNotExist(statErr),
		"no .version file should exist after failed download")
}

// =============================================================================
// 39. VERSION FILE CONTENT VALIDATION
//     Verify malicious .version file content is rejected.
// =============================================================================

func TestSecurity_VersionFileContentValidation(t *testing.T) {
	maliciousVersions := []string{
		"../../../etc/evil",
		"v1.0.0\x00injected",
		"v1.0.0?query=true",
		"v1.0.0 with spaces",
		"",
		"\n\n\n",
	}

	for _, content := range maliciousVersions {
		t.Run(fmt.Sprintf("content=%q", content), func(t *testing.T) {
			cfg := testConfig(t)
			spec := BinarySpec{Name: "test-binary"}

			// Write malicious .version file
			versionPath, err := cfg.cachedVersionPath(spec)
			require.NoError(t, err)
			require.NoError(t, os.MkdirAll(filepath.Dir(versionPath), 0755))
			require.NoError(t, os.WriteFile(versionPath, []byte(content), 0644))

			_, readErr := cfg.readCachedVersion(spec)
			assert.Error(t, readErr, "malicious version %q should be rejected", content)
		})
	}
}

// =============================================================================
// 40. VERSION MISMATCH DOES NOT SERVE STALE BINARY
//     When source is reachable but download fails, should error,
//     not fall back to stale cached binary.
// =============================================================================

func TestSecurity_VersionMismatchDoesNotServeStale(t *testing.T) {
	legitimateContent := []byte("#!/bin/sh\necho good\n")
	legitimateTarGz := createTestTarGz(t, "test-binary", legitimateContent)

	spec := BinarySpec{
		Name:         "test-binary",
		AssetPattern: "{name}-{os}-{arch}.tar.gz",
	}
	asset := assetName(spec)

	// First: successful download of v1.0.0
	server := setupTestDownloadServer(t, map[string][]byte{
		"/v1.0.0/" + asset: legitimateTarGz,
	})
	spec.Source = &testSource{version: "v1.0.0", serverURL: server.URL}
	cfg := testConfig(t)

	result, err := cfg.resolve(context.Background(), spec, "")
	require.NoError(t, err)

	// Verify v1 is cached
	ver, _ := cfg.readCachedVersion(spec)
	assert.Equal(t, "v1.0.0", ver)

	// Second: source says v2.0.0 but download 404s
	server2 := setupTestDownloadServer(t, map[string][]byte{})
	spec.Source = &testSource{version: "v2.0.0", serverURL: server2.URL}

	_, err = cfg.resolve(context.Background(), spec, "")
	assert.Error(t, err, "should error when download fails, not serve stale v1")

	// v1 binary should still be on disk (not deleted)
	content, _ := os.ReadFile(result)
	assert.Equal(t, legitimateContent, content)

	// .version should still say v1.0.0 (not updated to v2.0.0)
	ver, _ = cfg.readCachedVersion(spec)
	assert.Equal(t, "v1.0.0", ver)
}
