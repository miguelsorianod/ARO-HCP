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

	azcorearm "github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armlocks"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
)

func ListByType(
	ctx context.Context,
	client *armresources.Client,
	resourceGroupName string,
	resourceType string,
) ([]*armresources.GenericResourceExpanded, error) {
	filter := fmt.Sprintf("resourceType eq '%s'", resourceType)
	pager := client.NewListByResourceGroupPager(resourceGroupName, &armresources.ClientListByResourceGroupOptions{
		Filter: &filter,
	})

	var resources []*armresources.GenericResourceExpanded
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list resources of type %s: %w", resourceType, err)
		}
		resources = append(resources, page.Value...)
	}
	return resources, nil
}

func HasLocks(ctx context.Context, locksClient *armlocks.ManagementLocksClient, resourceID string) bool {
	parsedID, err := azcorearm.ParseResourceID(resourceID)
	if err != nil {
		return false
	}

	parentResourcePath := ""
	if parsedID.Parent != nil {
		parentResourcePath = parsedID.Parent.String()
	}

	pager := locksClient.NewListAtResourceLevelPager(
		parsedID.ResourceGroupName,
		parsedID.ResourceType.Namespace,
		parentResourcePath,
		parsedID.ResourceType.Type,
		parsedID.Name,
		nil,
	)

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return false
		}
		if len(page.Value) > 0 {
			return true
		}
	}
	return false
}

func DeleteByID(
	ctx context.Context,
	client *armresources.Client,
	resourceID string,
	apiVersion string,
	wait bool,
) error {
	poller, err := client.BeginDeleteByID(ctx, resourceID, apiVersion, nil)
	if err != nil {
		return err
	}
	if wait {
		_, err = poller.PollUntilDone(ctx, nil)
		return err
	}
	return nil
}
