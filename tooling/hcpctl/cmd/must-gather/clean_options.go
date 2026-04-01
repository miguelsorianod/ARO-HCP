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

package mustgather

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"

	"github.com/Azure/ARO-HCP/tooling/hcpctl/pkg/binresolver"
)

type RawCleanOptions struct {
	PathToClean            string
	ServiceConfigPath      string
	MustGatherCleanBinary  string
	MustGatherCleanVersion string
	CleanedOutputPath      string
	CleanConfigPath        string
	CacheDir               string
}

func DefaultCleanOptions() *RawCleanOptions {
	return &RawCleanOptions{
		PathToClean: "must-gather-clean",
	}
}
func (opts *RawCleanOptions) Run(ctx context.Context) error {
	validated, err := opts.Validate(ctx)
	if err != nil {
		return err
	}

	completed, err := validated.Complete(ctx)
	if err != nil {
		return err
	}
	// defer os.RemoveAll(completed.WorkingDir)

	return completed.Run(ctx)
}
func BindCleanOptions(opts *RawCleanOptions, cmd *cobra.Command) error {
	cmd.Flags().StringVar(&opts.PathToClean, "path-to-clean", opts.PathToClean, "Path to clean")
	cmd.Flags().StringVar(&opts.ServiceConfigPath, "service-config-path", opts.ServiceConfigPath, "Path to ARO-HCP Service Configuration file (not must-gather-clean config)")
	cmd.Flags().StringVar(&opts.MustGatherCleanBinary, "must-gather-clean-binary", opts.MustGatherCleanBinary, "Optional path to must-gather-clean binary. If omitted, the release is automatically downloaded and cached.")
	cmd.Flags().StringVar(&opts.MustGatherCleanVersion, "must-gather-clean-version", opts.MustGatherCleanVersion, "Pin must-gather-clean to a specific release version (e.g. v0.1.0). If omitted, the latest release is used.")
	cmd.Flags().StringVar(&opts.CleanedOutputPath, "cleaned-output-path", opts.CleanedOutputPath, "Path to cleaned output")
	cmd.Flags().StringVar(&opts.CleanConfigPath, "clean-config-path", opts.CleanConfigPath, "Path to must-gather-clean config, will be extended with ARO-HCP Service Configuration literals")
	cmd.Flags().StringVar(&opts.CacheDir, "cache-dir", opts.CacheDir, "Override cache directory for downloaded binaries. Defaults to OS cache dir. Can also be set via HCPCTL_CACHE_DIR env var.")

	if err := cmd.MarkFlagDirname("path-to-clean"); err != nil {
		return fmt.Errorf("failed to mark flag %q as a file: %w", "path-to-clean", err)
	}
	if err := cmd.MarkFlagRequired("path-to-clean"); err != nil {
		return fmt.Errorf("failed to mark flag %q as required: %w", "path-to-clean", err)
	}
	if err := cmd.MarkFlagDirname("service-config-path"); err != nil {
		return fmt.Errorf("failed to mark flag %q as a file: %w", "service-config-path", err)
	}
	if err := cmd.MarkFlagRequired("service-config-path"); err != nil {
		return fmt.Errorf("failed to mark flag %q as a required: %w", "service-config-path", err)
	}
	if err := cmd.MarkFlagFilename("must-gather-clean-binary"); err != nil {
		return fmt.Errorf("failed to mark flag %q as a file: %w", "must-gather-clean-binary", err)
	}
	if err := cmd.MarkFlagDirname("cleaned-output-path"); err != nil {
		return fmt.Errorf("failed to mark flag %q as a directory: %w", "cleaned-output-path", err)
	}
	if err := cmd.MarkFlagDirname("cache-dir"); err != nil {
		return fmt.Errorf("failed to mark flag %q as a directory: %w", "cache-dir", err)
	}
	return nil
}

type ValidatedCleanOptions struct {
	*RawCleanOptions
}

type CleanOptions struct {
	*ValidatedCleanOptions
	WorkingDir string
}

func (opts *RawCleanOptions) Validate(ctx context.Context) (*ValidatedCleanOptions, error) {
	if opts.PathToClean == "" {
		return nil, fmt.Errorf("path-to-clean is required")
	}
	if opts.ServiceConfigPath == "" {
		return nil, fmt.Errorf("service-config-path is required")
	}
	if opts.CleanedOutputPath == "" {
		return nil, fmt.Errorf("cleaned-output-path is required")
	}
	if opts.CacheDir != "" {
		if !filepath.IsAbs(opts.CacheDir) {
			return nil, fmt.Errorf("cache-dir must be an absolute path, got %q", opts.CacheDir)
		}
	}

	return &ValidatedCleanOptions{
		RawCleanOptions: opts,
	}, nil
}

func (opts *ValidatedCleanOptions) Complete(ctx context.Context) (*CleanOptions, error) {
	logger := logr.FromContextOrDiscard(ctx)

	resolvedBinary, err := binresolver.ResolveMustGatherClean(ctx, opts.MustGatherCleanBinary, opts.MustGatherCleanVersion, opts.CacheDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve must-gather-clean binary: %w", err)
	}
	logger.V(1).Info("using must-gather-clean binary", "path", resolvedBinary)
	opts.MustGatherCleanBinary = resolvedBinary

	workingDir, err := os.MkdirTemp("", "must-gather-clean-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create working directory: %w", err)
	}

	return &CleanOptions{
		ValidatedCleanOptions: opts,
		WorkingDir:            workingDir,
	}, nil
}
