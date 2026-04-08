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

package arm

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
)

// APIVersionCache caches API versions by resource type and resolves misses
// through ARM provider metadata.
type APIVersionCache struct {
	providersClient *armresources.ProvidersClient
	mu              sync.Mutex
	cache           map[string]string
}

// NewAPIVersionCache creates an empty API-version cache.
func NewAPIVersionCache(providersClient *armresources.ProvidersClient) *APIVersionCache {
	return &APIVersionCache{
		providersClient: providersClient,
		cache:           make(map[string]string),
	}
}

// Get returns an API version for the given ARM resource type.
func (c *APIVersionCache) Get(ctx context.Context, resourceType string) (string, error) {
	normalizedResourceType := normalizeResourceType(resourceType)
	if normalizedResourceType == "" {
		return "", fmt.Errorf("resource type is required")
	}

	c.mu.Lock()
	cachedAPIVersion, found := c.cache[normalizedResourceType]
	c.mu.Unlock()
	if found {
		return cachedAPIVersion, nil
	}

	if c.providersClient == nil {
		return "", fmt.Errorf("providers client is required to resolve API version for %s", resourceType)
	}

	resolvedAPIVersion, err := resolveAPIVersion(ctx, c.providersClient, resourceType)
	if err != nil {
		return "", fmt.Errorf("failed to get API version for %s: %w", resourceType, err)
	}

	c.mu.Lock()
	// Another goroutine may have populated the value while this one resolved it.
	if cachedAPIVersion, found := c.cache[normalizedResourceType]; found {
		c.mu.Unlock()
		return cachedAPIVersion, nil
	}
	c.cache[normalizedResourceType] = resolvedAPIVersion
	c.mu.Unlock()

	return resolvedAPIVersion, nil
}

// Set stores a resource type to API version mapping in the cache.
func (c *APIVersionCache) Set(resourceType, apiVersion string) {
	normalizedResourceType := normalizeResourceType(resourceType)
	trimmedAPIVersion := strings.TrimSpace(apiVersion)
	if normalizedResourceType == "" || trimmedAPIVersion == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[normalizedResourceType] = trimmedAPIVersion
}

func normalizeResourceType(resourceType string) string {
	return strings.ToLower(strings.TrimSpace(resourceType))
}

func resolveAPIVersion(
	ctx context.Context,
	providersClient *armresources.ProvidersClient,
	resourceType string,
) (string, error) {
	trimmedResourceType := strings.TrimSpace(resourceType)
	var providerNamespace, resourceTypeName string
	if idx := strings.Index(trimmedResourceType, "/"); idx > 0 {
		providerNamespace = trimmedResourceType[:idx]
		resourceTypeName = trimmedResourceType[idx+1:]
	} else {
		return "", fmt.Errorf("invalid resource type format: %s", resourceType)
	}

	provider, err := providersClient.Get(ctx, providerNamespace, nil)
	if err != nil {
		return "", fmt.Errorf("failed to get provider metadata for %s: %w", providerNamespace, err)
	}

	if provider.ResourceTypes != nil {
		for _, rt := range provider.ResourceTypes {
			if rt.ResourceType != nil && strings.EqualFold(*rt.ResourceType, resourceTypeName) && len(rt.APIVersions) > 0 {
				for _, version := range rt.APIVersions {
					if version != nil {
						return *version, nil
					}
				}
				if rt.APIVersions[0] != nil {
					return *rt.APIVersions[0], nil
				}
			}
		}
	}
	return "", fmt.Errorf("resource type %s not found in provider %s metadata", resourceTypeName, providerNamespace)
}
