#!/usr/bin/env bash

# Copyright 2026 Microsoft Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o nounset
set -o pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

JQ="${1:-jq}"

JQ_SORT_KEYS='def sort_keys: if type == "object" then to_entries | sort_by(.key) | map(.value |= sort_keys) | from_entries elif type == "array" then map(sort_keys) else . end; sort_keys'

while IFS= read -r -d '' f; do
  "${JQ}" --tab "${JQ_SORT_KEYS}" "$f" > "${f}.tmp" && mv "${f}.tmp" "$f"
done < <(find "${REPO_ROOT}/test-integration" -name '*.json' -print0)
