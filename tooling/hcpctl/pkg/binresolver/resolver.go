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
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/go-logr/logr"
)

// Source provides methods to query and download binaries from a release source.
type Source interface {
	LatestTagName(ctx context.Context) (string, error)
	Download(ctx context.Context, version, asset string, w io.Writer) error
}

// BinarySpec defines a downloadable binary.
type BinarySpec struct {
	Name                string // binary name, e.g. "must-gather-clean"
	Source              Source // where to download from (e.g. GitHubSource)
	AssetPattern        string // template for non-Windows: "{name}-{os}-{arch}.tar.gz"
	WindowsAssetPattern string // template for Windows: "{name}-{os}-{arch}.exe.zip"
	ChecksumAsset       string // release asset containing SHA256 checksums (e.g. "SHA256_SUM")
	PinnedVersion       string // pin to a specific version (e.g. "v0.0.3") via --must-gather-clean-version; empty means use latest
}

// resolverConfig holds configuration for resolving and downloading binaries.
type resolverConfig struct {
	cacheRoot string
}

// Resolve returns the path to the binary. It checks in order:
// 1. An explicit path provided by the user (verified to exist).
// 2. The locally cached binary, if its version matches the latest release.
// 3. The latest release, downloaded and cached when a newer version is available.
// 4. A previously cached binary as a fallback when the source is unreachable.
//
// cacheDir overrides the default cache directory. If empty, HCPCTL_CACHE_DIR
// env var is checked, then the OS user cache directory is used.
func Resolve(ctx context.Context, spec BinarySpec, explicitPath, cacheDir string) (string, error) {
	cfg := resolverConfig{cacheRoot: cacheDir}
	return cfg.resolve(ctx, spec, explicitPath)
}

func (cfg *resolverConfig) resolve(ctx context.Context, spec BinarySpec, explicitPath string) (string, error) {
	logger := logr.FromContextOrDiscard(ctx)

	if explicitPath != "" {
		info, err := os.Stat(explicitPath)
		if err != nil {
			return "", fmt.Errorf("failed to find binary at explicit path %q: %w", explicitPath, err)
		}
		if info.IsDir() {
			return "", fmt.Errorf("explicit path %q is a directory, not a binary", explicitPath)
		}
		logger.V(1).Info("using explicit binary path", "path", explicitPath)
		return explicitPath, nil
	}

	if err := validateName(spec.Name); err != nil {
		return "", err
	}

	if spec.Source == nil {
		return "", fmt.Errorf("no source configured for %q binary", spec.Name)
	}

	var version string
	if spec.PinnedVersion != "" {
		if err := validateVersion(spec.PinnedVersion); err != nil {
			return "", fmt.Errorf("invalid pinned version: %w", err)
		}
		version = spec.PinnedVersion
		logger.V(1).Info("using pinned version", "version", version)
	} else {
		var err error
		version, err = spec.Source.LatestTagName(ctx)
		if err == nil {
			if verr := validateVersion(version); verr != nil {
				return "", verr
			}
		}
		if err != nil {
			logger.V(1).Info("failed to query for latest version, attempting cache fallback", "error", err)
			cached, fallbackErr := cfg.findAnyCached(spec)
			if fallbackErr != nil {
				return "", fmt.Errorf("failed to get latest version and no cached binary found; "+
					"you can manually download the binary and provide it via %s: %w", "--"+spec.Name+"-binary", err)
			}
			if cachedVer, verErr := cfg.readCachedVersion(spec); verErr == nil {
				logger.V(1).Info("using cached binary (source unreachable)", "path", cached, "version", cachedVer)
			} else {
				logger.V(1).Info("using cached binary (source unreachable, version unknown)", "path", cached)
			}
			return cached, nil
		}
	}

	binPath, err := cfg.cachedBinaryPath(spec)
	if err != nil {
		return "", fmt.Errorf("failed to determine cache path; "+
			"you can manually provide the binary via %s: %w", "--"+spec.Name+"-binary", err)
	}

	cachedVersion, versionErr := cfg.readCachedVersion(spec)
	if versionErr == nil && cachedVersion == version {
		if _, statErr := os.Stat(binPath); statErr == nil {
			logger.V(1).Info("cached binary is up to date", "path", binPath, "version", version)
			return binPath, nil
		}
		logger.V(1).Info("version file present but binary missing, re-downloading", "version", version)
	}

	logger.V(1).Info("downloading binary", "name", spec.Name, "version", version)
	if err := cfg.download(ctx, spec, version, binPath); err != nil {
		return "", fmt.Errorf("failed to download %s %s for %s/%s; "+
			"you can manually provide it via %s: %w",
			spec.Name, version, runtime.GOOS, runtime.GOARCH, "--"+spec.Name+"-binary", err)
	}

	if err := cfg.writeCachedVersion(spec, version); err != nil {
		logger.V(1).Info("failed to write version file (binary is still usable)", "error", err)
	}

	logger.V(1).Info("binary downloaded and cached", "path", binPath, "version", version)
	return binPath, nil
}

func (cfg *resolverConfig) download(ctx context.Context, spec BinarySpec, version, destPath string) error {
	asset := assetName(spec)

	// Create temp file for download
	tmpFile, err := os.CreateTemp("", "binresolver-download-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	// Source handles download with retries
	if err := spec.Source.Download(ctx, version, asset, tmpFile); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to download asset: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to flush downloaded asset to disk: %w", err)
	}

	info, err := os.Stat(tmpPath)
	if err != nil {
		return fmt.Errorf("failed to stat downloaded archive: %w", err)
	}
	if info.Size() > maxArchiveSize {
		return fmt.Errorf("downloaded archive exceeds maximum allowed size (%d MB)", maxArchiveSize>>20)
	}

	if err := cfg.verifyChecksum(ctx, spec, version, asset, tmpPath); err != nil {
		return fmt.Errorf("checksum verification failed: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return fmt.Errorf("failed to create cache directory %q (check write permissions): %w", filepath.Dir(destPath), err)
	}

	extractTmpFile, err := os.CreateTemp(filepath.Dir(destPath), filepath.Base(destPath)+".tmp.*")
	if err != nil {
		return fmt.Errorf("failed to create temp file for extraction: %w", err)
	}
	extractTmp := extractTmpFile.Name()
	extractTmpFile.Close()
	defer os.Remove(extractTmp)

	if strings.HasSuffix(asset, ".tar.gz") {
		if err := extractTarGz(tmpPath, spec.Name, extractTmp); err != nil {
			return fmt.Errorf("failed to extract tar.gz archive: %w", err)
		}
	} else if strings.HasSuffix(asset, ".zip") {
		if err := extractZip(tmpPath, spec.Name, extractTmp); err != nil {
			return fmt.Errorf("failed to extract zip archive: %w", err)
		}
	} else {
		return fmt.Errorf("unsupported asset format: %s", asset)
	}

	if err := os.Chmod(extractTmp, 0755); err != nil {
		return fmt.Errorf("failed to set binary permissions: %w", err)
	}

	if err := os.Rename(extractTmp, destPath); err != nil {
		if _, statErr := os.Stat(destPath); statErr != nil {
			return fmt.Errorf("failed to move extracted binary to cache: %w", err)
		}
	}

	return nil
}

const maxBinarySize = 256 << 20     // 256 MB
const maxArchiveSize = 512 << 20    // 512 MB
const maxChecksumFileSize = 1 << 20 // 1 MB

type limitedWriter struct {
	w        io.Writer
	n        int64
	limit    int64
	overflow bool
}

func (lw *limitedWriter) Write(p []byte) (int, error) {
	if lw.n+int64(len(p)) > lw.limit {
		lw.overflow = true
		return len(p), nil
	}
	n, err := lw.w.Write(p)
	lw.n += int64(n)
	return n, err
}

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

	var buf bytes.Buffer
	lw := &limitedWriter{w: &buf, limit: maxChecksumFileSize}
	if err := spec.Source.Download(ctx, version, spec.ChecksumAsset, lw); err != nil {
		return fmt.Errorf("failed to download checksum file %q: %w", spec.ChecksumAsset, err)
	}

	if lw.overflow {
		return fmt.Errorf("checksum file %q exceeds maximum allowed size (%d bytes)", spec.ChecksumAsset, maxChecksumFileSize)
	}

	body := buf.Bytes()

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
			return fmt.Errorf("invalid checksum entry for %q in %q: hash is %d characters, expected 64",
				assetFileName, spec.ChecksumAsset, len(hash))
		}
		if _, err := hex.DecodeString(hash); err != nil {
			return fmt.Errorf("invalid checksum entry for %q in %q: hash is not valid hex: %w",
				assetFileName, spec.ChecksumAsset, err)
		}
		expectedHash = hash
		break
	}

	if expectedHash == "" {
		return fmt.Errorf("asset %q not found in checksum file %q", assetFileName, spec.ChecksumAsset)
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

func validateVersion(version string) error {
	if version == "" {
		return fmt.Errorf("version string must not be empty")
	}
	if strings.ContainsAny(version, "\x00") {
		return fmt.Errorf("invalid version string from source: %q (contains null byte)", version)
	}
	if strings.ContainsAny(version, `/\`) {
		return fmt.Errorf("invalid version string from source: %q", version)
	}
	if version == ".." {
		return fmt.Errorf("invalid version string from source: %q", version)
	}
	if strings.ContainsAny(version, "?#") {
		return fmt.Errorf("invalid version string from source: %q (contains URL-unsafe characters)", version)
	}
	if strings.ContainsAny(version, " \t\n\r") {
		return fmt.Errorf("invalid version string from source: %q (contains whitespace)", version)
	}
	return nil
}

func validateName(name string) error {
	if name == "" {
		return fmt.Errorf("binary name must not be empty")
	}
	if strings.ContainsAny(name, "\x00") {
		return fmt.Errorf("invalid binary name %q: must not contain null bytes", name)
	}
	if name == "." {
		return fmt.Errorf("invalid binary name %q: must not be '.'", name)
	}

	// Reject both native and non-native separators to prevent cross-platform path traversal.
	hasNativeSeparator := strings.ContainsRune(name, os.PathSeparator)
	hasNonNativeSeparator := (os.PathSeparator == '/' && strings.ContainsRune(name, '\\')) ||
		(os.PathSeparator == '\\' && strings.ContainsRune(name, '/'))
	if hasNativeSeparator || hasNonNativeSeparator {
		return fmt.Errorf("invalid binary name %q: must not contain path separators", name)
	}
	if !filepath.IsLocal(name) {
		return fmt.Errorf("invalid binary name %q: must be a local path component", name)
	}
	return nil
}

func binaryFileName(spec BinarySpec) string {
	name := spec.Name
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
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
		root = os.Getenv("HCPCTL_CACHE_DIR")
	}
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

func (cfg *resolverConfig) cachedBinaryPath(spec BinarySpec) (string, error) {
	baseDir, err := cfg.cacheBaseDir(spec)
	if err != nil {
		return "", err
	}
	return filepath.Join(baseDir, binaryFileName(spec)), nil
}

func (cfg *resolverConfig) cachedVersionPath(spec BinarySpec) (string, error) {
	baseDir, err := cfg.cacheBaseDir(spec)
	if err != nil {
		return "", err
	}
	return filepath.Join(baseDir, ".version"), nil
}

func (cfg *resolverConfig) readCachedVersion(spec BinarySpec) (string, error) {
	versionPath, err := cfg.cachedVersionPath(spec)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(versionPath)
	if err != nil {
		return "", err
	}
	version := strings.TrimSpace(string(data))
	if err := validateVersion(version); err != nil {
		return "", fmt.Errorf("cached version file contains invalid content: %w", err)
	}
	return version, nil
}

func (cfg *resolverConfig) writeCachedVersion(spec BinarySpec, version string) error {
	versionPath, err := cfg.cachedVersionPath(spec)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(versionPath), 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}
	tmpFile, err := os.CreateTemp(filepath.Dir(versionPath), ".version.tmp.*")
	if err != nil {
		return fmt.Errorf("failed to create temp version file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.WriteString(version + "\n"); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to write version file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close version file: %w", err)
	}
	if err := os.Rename(tmpPath, versionPath); err != nil {
		return fmt.Errorf("failed to atomically update version file: %w", err)
	}
	return nil
}

func (cfg *resolverConfig) findAnyCached(spec BinarySpec) (string, error) {
	baseDir, err := cfg.cacheBaseDir(spec)
	if err != nil {
		return "", err
	}

	binPath := filepath.Join(baseDir, binaryFileName(spec))
	if _, err := os.Stat(binPath); err != nil {
		return "", fmt.Errorf("no cached binary found for %s", spec.Name)
	}
	return binPath, nil
}
