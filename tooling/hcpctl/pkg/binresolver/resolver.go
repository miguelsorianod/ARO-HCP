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
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/go-logr/logr"
)

// Source knows how to find the latest version and provide download URLs for a binary.
type Source interface {
	LatestVersion(ctx context.Context, client *http.Client) (string, error)
	DownloadURL(version, asset string) string
}

// BinarySpec defines a downloadable binary.
type BinarySpec struct {
	Name                string // binary name, e.g. "must-gather-clean"
	Source              Source // where to download from (e.g. GitHubSource)
	AssetPattern        string // template for non-Windows: "{name}-{os}-{arch}.tar.gz"
	WindowsAssetPattern string // template for Windows: "{name}-{os}-{arch}.exe.zip"
	ChecksumAsset       string // release asset containing SHA256 checksums (e.g. "SHA256_SUM")
}

// resolverConfig holds configuration for resolving and downloading binaries.
type resolverConfig struct {
	cacheRoot  string
	httpClient *http.Client
}

var defaultConfig = resolverConfig{
	httpClient: &http.Client{Timeout: 60 * time.Second},
}

// Resolve returns the path to the binary. It checks in order:
// 1. An explicit path provided by the user (verified to exist).
// 2. The latest release version, using a locally cached copy if available.
// 3. A previously cached version as a fallback when the source is unreachable.
// If no cached binary exists, the latest release is downloaded and cached.
func Resolve(ctx context.Context, spec BinarySpec, explicitPath string) (string, error) {
	return defaultConfig.resolve(ctx, spec, explicitPath)
}

func (cfg *resolverConfig) resolve(ctx context.Context, spec BinarySpec, explicitPath string) (string, error) {
	logger := logr.FromContextOrDiscard(ctx)

	if explicitPath != "" {
		if _, err := os.Stat(explicitPath); err != nil {
			return "", fmt.Errorf("failed to find binary at explicit path %q: %w", explicitPath, err)
		}
		logger.V(1).Info("using explicit binary path", "path", explicitPath)
		return explicitPath, nil
	}

	if spec.Source == nil {
		return "", fmt.Errorf("no source configured for %q binary", spec.Name)
	}

	version, err := spec.Source.LatestVersion(ctx, cfg.httpClient)
	if err != nil {
		logger.V(1).Info("failed to query for latest version, attempting cache fallback", "error", err)
		cached, fallbackErr := cfg.findAnyCached(spec)
		if fallbackErr != nil {
			return "", fmt.Errorf("failed to get latest version and no cached binary found; "+
				"you can manually download the binary and provide it via %s: %w", "--"+spec.Name+"-binary", err)
		}
		logger.V(1).Info("using cached binary (may be outdated)", "path", cached)
		return cached, nil
	}

	binPath, err := cfg.cachedBinaryPath(spec, version)
	if err != nil {
		return "", fmt.Errorf("failed to determine cache path; "+
			"you can manually provide the binary via %s: %w", "--"+spec.Name+"-binary", err)
	}

	if _, err := os.Stat(binPath); err == nil {
		logger.V(4).Info("using cached binary", "path", binPath, "version", version)
		return binPath, nil
	}

	logger.V(1).Info("downloading binary", "name", spec.Name, "version", version)
	if err := cfg.download(ctx, spec, version, binPath); err != nil {
		return "", fmt.Errorf("failed to download %s %s for %s/%s; "+
			"you can manually provide it via %s: %w",
			spec.Name, version, runtime.GOOS, runtime.GOARCH, "--"+spec.Name+"-binary", err)
	}

	if err := cfg.cleanOldVersions(spec, version); err != nil {
		logger.V(1).Info("failed to clean old cached versions", "error", err)
	}

	logger.V(1).Info("binary downloaded and cached", "path", binPath, "version", version)
	return binPath, nil
}

func (cfg *resolverConfig) download(ctx context.Context, spec BinarySpec, version, destPath string) error {
	asset := assetName(spec)
	url := spec.Source.DownloadURL(version, asset)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create download request: %w", err)
	}

	resp, err := cfg.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download asset: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned status %d for %s", resp.StatusCode, url)
	}

	tmpFile, err := os.CreateTemp("", "binresolver-download-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := io.Copy(tmpFile, io.LimitReader(resp.Body, maxArchiveSize+1)); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to write downloaded asset: %w", err)
	}

	n, _ := tmpFile.Seek(0, io.SeekCurrent)
	if n > maxArchiveSize {
		tmpFile.Close()
		return fmt.Errorf("downloaded archive exceeds maximum allowed size (%d MB)", maxArchiveSize>>20)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to flush downloaded asset to disk: %w", err)
	}

	if err := cfg.verifyChecksum(ctx, spec, version, asset, tmpFile.Name()); err != nil {
		return fmt.Errorf("checksum verification failed: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return fmt.Errorf("failed to create cache directory %q (check write permissions): %w", filepath.Dir(destPath), err)
	}

	if strings.HasSuffix(asset, ".tar.gz") {
		if err := extractTarGz(tmpFile.Name(), spec.Name, destPath); err != nil {
			return fmt.Errorf("failed to extract tar.gz archive: %w", err)
		}
	} else if strings.HasSuffix(asset, ".zip") {
		if err := extractZip(tmpFile.Name(), spec.Name, destPath); err != nil {
			return fmt.Errorf("failed to extract zip archive: %w", err)
		}
	} else {
		return fmt.Errorf("unsupported asset format: %s", asset)
	}

	return nil
}

const maxBinarySize = 256 << 20     // 256 MB
const maxArchiveSize = 512 << 20    // 512 MB
const maxChecksumFileSize = 1 << 20 // 1 MB

func writeExtractedBinary(src io.Reader, binaryName, destPath string) error {
	out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("failed to create binary file: %w", err)
	}

	n, copyErr := io.Copy(out, io.LimitReader(src, maxBinarySize+1))
	if closeErr := out.Close(); closeErr != nil && copyErr == nil {
		return fmt.Errorf("failed to close extracted binary: %w", closeErr)
	}
	if copyErr != nil {
		return fmt.Errorf("failed to extract binary: %w", copyErr)
	}
	if n > maxBinarySize {
		os.Remove(destPath)
		return fmt.Errorf("binary %q exceeds maximum allowed size (%d MB)", binaryName, maxBinarySize>>20)
	}
	return nil
}

func extractTarGz(archivePath, binaryName, destPath string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("failed to open archive: %w", err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar entry: %w", err)
		}

		if filepath.Base(header.Name) == binaryName && header.Typeflag == tar.TypeReg {
			return writeExtractedBinary(tr, binaryName, destPath)
		}
	}

	return fmt.Errorf("binary %q not found in archive", binaryName)
}

func extractZip(archivePath, binaryName, destPath string) error {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("failed to open zip archive: %w", err)
	}
	defer r.Close()

	winBinaryName := binaryName + ".exe"
	for _, f := range r.File {
		name := filepath.Base(f.Name)
		if name != binaryName && name != winBinaryName {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("failed to open zip entry: %w", err)
		}
		err = writeExtractedBinary(rc, binaryName, destPath)
		rc.Close()
		return err
	}

	return fmt.Errorf("binary %q not found in zip archive", binaryName)
}

func (cfg *resolverConfig) verifyChecksum(ctx context.Context, spec BinarySpec, version, assetFileName, archivePath string) error {
	if spec.ChecksumAsset == "" {
		return nil
	}
	logger := logr.FromContextOrDiscard(ctx)

	url := spec.Source.DownloadURL(version, spec.ChecksumAsset)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		logger.V(1).Info(
			"checksum verification skipped",
			"reason", "request_creation_failed",
			"asset", assetFileName,
			"checksumAsset", spec.ChecksumAsset,
			"error", err,
		)
		return nil
	}

	resp, err := cfg.httpClient.Do(req)
	if err != nil {
		logger.V(1).Info(
			"checksum verification skipped",
			"reason", "download_failed",
			"asset", assetFileName,
			"checksumAsset", spec.ChecksumAsset,
			"error", err,
		)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.V(1).Info(
			"checksum verification skipped",
			"reason", "checksum_unavailable",
			"asset", assetFileName,
			"checksumAsset", spec.ChecksumAsset,
			"status", resp.StatusCode,
		)
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxChecksumFileSize+1))
	if err != nil {
		logger.V(1).Info(
			"checksum verification skipped",
			"reason", "checksum_read_failed",
			"asset", assetFileName,
			"checksumAsset", spec.ChecksumAsset,
			"error", err,
		)
		return nil
	}
	if len(body) > maxChecksumFileSize {
		logger.V(1).Info(
			"checksum verification skipped",
			"reason", "checksum_too_large",
			"asset", assetFileName,
			"checksumAsset", spec.ChecksumAsset,
			"maxSizeBytes", maxChecksumFileSize,
		)
		return nil
	}

	var expectedHash string
	for line := range strings.SplitSeq(string(body), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		checksumEntryName := strings.TrimPrefix(parts[len(parts)-1], "*")
		if filepath.Base(checksumEntryName) != assetFileName {
			continue
		}

		hash := strings.ToLower(parts[0])
		if len(hash) != 64 {
			logger.V(1).Info(
				"checksum verification skipped",
				"reason", "invalid_checksum_entry",
				"asset", assetFileName,
				"checksumAsset", spec.ChecksumAsset,
			)
			return nil
		}
		if _, err := hex.DecodeString(hash); err != nil {
			logger.V(1).Info(
				"checksum verification skipped",
				"reason", "invalid_checksum_entry",
				"asset", assetFileName,
				"checksumAsset", spec.ChecksumAsset,
			)
			return nil
		}
		expectedHash = hash
		break
	}

	if expectedHash == "" {
		logger.V(1).Info(
			"checksum verification skipped",
			"reason", "asset_not_in_checksum",
			"asset", assetFileName,
			"checksumAsset", spec.ChecksumAsset,
		)
		return nil
	}

	f, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("failed to open archive for checksum verification: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("failed to compute checksum: %w", err)
	}

	actualHash := fmt.Sprintf("%x", h.Sum(nil))
	if actualHash != expectedHash {
		return fmt.Errorf("checksum mismatch for %s: expected %s, got %s", assetFileName, expectedHash, actualHash)
	}

	logger.V(4).Info("checksum verified", "asset", assetFileName, "sha256", actualHash)
	return nil
}

func assetName(spec BinarySpec) string {
	pattern := spec.AssetPattern
	if runtime.GOOS == "windows" && spec.WindowsAssetPattern != "" {
		pattern = spec.WindowsAssetPattern
	}
	r := strings.NewReplacer(
		"{name}", spec.Name,
		"{os}", runtime.GOOS,
		"{arch}", runtime.GOARCH,
	)
	return r.Replace(pattern)
}

func (cfg *resolverConfig) cacheBaseDir(spec BinarySpec) (string, error) {
	root := cfg.cacheRoot
	if root == "" {
		var err error
		root, err = os.UserCacheDir()
		if err != nil {
			return "", fmt.Errorf("failed to determine user cache directory: %w", err)
		}
		root = filepath.Join(root, "hcpctl", "bin")
	}
	return filepath.Join(root, spec.Name), nil
}

func (cfg *resolverConfig) cachedBinaryPath(spec BinarySpec, version string) (string, error) {
	baseDir, err := cfg.cacheBaseDir(spec)
	if err != nil {
		return "", err
	}
	binaryName := spec.Name
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	return filepath.Join(baseDir, version, binaryName), nil
}

func (cfg *resolverConfig) cleanOldVersions(spec BinarySpec, currentVersion string) error {
	baseDir, err := cfg.cacheBaseDir(spec)
	if err != nil {
		return err
	}

	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return fmt.Errorf("failed to read cache directory: %w", err)
	}

	var errs []error
	for _, entry := range entries {
		if entry.IsDir() && entry.Name() != currentVersion {
			if err := os.RemoveAll(filepath.Join(baseDir, entry.Name())); err != nil {
				errs = append(errs, fmt.Errorf("failed to remove old version %s: %w", entry.Name(), err))
			}
		}
	}

	return errors.Join(errs...)
}

func (cfg *resolverConfig) findAnyCached(spec BinarySpec) (string, error) {
	baseDir, err := cfg.cacheBaseDir(spec)
	if err != nil {
		return "", err
	}

	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return "", fmt.Errorf("failed to read cache directory: %w", err)
	}

	binaryName := spec.Name
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}

	type cachedCandidate struct {
		path    string
		modTime time.Time
	}
	var selected *cachedCandidate

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		candidate := filepath.Join(baseDir, entry.Name(), binaryName)
		info, err := os.Stat(candidate)
		if err != nil {
			continue
		}

		if selected == nil || info.ModTime().After(selected.modTime) {
			selected = &cachedCandidate{
				path:    candidate,
				modTime: info.ModTime(),
			}
		}
	}

	if selected != nil {
		return selected.path, nil
	}

	return "", fmt.Errorf("no cached binary found for %s", spec.Name)
}
