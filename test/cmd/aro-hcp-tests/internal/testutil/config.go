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

package testutil

import (
	"fmt"
	"os"

	"sigs.k8s.io/yaml"

	configtypes "github.com/Azure/ARO-Tools/config/types"
)

// ConfigGetString retrieves a string value from the configuration at the
// specified path. It returns an error if the path is missing or the value
// is not a string.
func ConfigGetString(cfg configtypes.Configuration, cfgPath string) (string, error) {
	val, err := cfg.GetByPath(cfgPath)
	if err != nil {
		return "", err
	}
	s, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("config value at %q is %T, not string", cfgPath, val)
	}
	return s, nil
}

// LoadRenderedConfig reads and unmarshals a rendered configuration YAML file.
func LoadRenderedConfig(path string) (configtypes.Configuration, error) {
	rawCfg, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read rendered config %s: %w", path, err)
	}
	var cfg configtypes.Configuration
	if err := yaml.Unmarshal(rawCfg, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal rendered config: %w", err)
	}
	return cfg, nil
}
