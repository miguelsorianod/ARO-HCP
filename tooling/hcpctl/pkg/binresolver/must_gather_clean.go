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

import "context"

// MustGatherClean is the BinarySpec for the openshift/must-gather-clean tool.
var MustGatherClean = BinarySpec{
	Name:                "must-gather-clean",
	Source:              &GitHubSource{Owner: "openshift", Repo: "must-gather-clean"},
	AssetPattern:        "{name}-{os}-{arch}.tar.gz",
	WindowsAssetPattern: "{name}-{os}-{arch}.exe.zip",
	ChecksumAsset:       "SHA256_SUM",
}

// ResolveMustGatherClean resolves the path to the must-gather-clean binary.
// If explicitPath is non-empty, it verifies the file exists and returns it.
// Otherwise, it downloads the release and caches it locally.
// version pins to a specific release (empty uses latest).
// cacheDir overrides the default cache directory (empty uses default).
func ResolveMustGatherClean(ctx context.Context, explicitPath, version, cacheDir string) (string, error) {
	spec := MustGatherClean
	if version != "" {
		spec.PinnedVersion = version
	}
	return Resolve(ctx, spec, explicitPath, cacheDir)
}
