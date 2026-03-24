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

package datadumpcontrollers

import (
	"context"
	"fmt"
	"net/http"

	arohcpv1alpha1 "github.com/openshift-online/ocm-sdk-go/arohcp/v1alpha1"

	"github.com/Azure/ARO-HCP/backend/pkg/controllers/controllerutils"
	"github.com/Azure/ARO-HCP/backend/pkg/listers"
	"github.com/Azure/ARO-HCP/internal/database"
	"github.com/Azure/ARO-HCP/internal/ocm"
	"github.com/Azure/ARO-HCP/internal/utils"
)

const (
	// CSStateWatcherConditionType is the condition type used by the CSStateWatcher controller
	CSStateWatcherConditionType = "ClusterServiceDegraded"
)

type csStateWatcher struct {
	cooldownChecker controllerutils.CooldownChecker
	cosmosClient    database.DBClient
	csClient        ocm.ClusterServiceClientSpec

	// nextSyncChecker ensures we don't hotloop from any source.
	nextSyncChecker controllerutils.CooldownChecker
}

// NewCSStateWatcherController watches cluster-service state and sets a degraded condition
// on the controller record if the cluster or any of its resources are in a failed or pending state.
// We do this so that we can see degraded in our metrics.  This also forms the basis for how we can report
// failures on the operation.
func NewCSStateWatcherController(activeOperationLister listers.ActiveOperationLister, cosmosClient database.DBClient, csClient ocm.ClusterServiceClientSpec) controllerutils.ClusterSyncer {
	c := &csStateWatcher{
		cooldownChecker: controllerutils.DefaultActiveOperationPrioritizingCooldown(activeOperationLister),
		cosmosClient:    cosmosClient,
		csClient:        csClient,
		nextSyncChecker: controllerutils.DefaultActiveOperationPrioritizingCooldown(activeOperationLister),
	}

	return c
}

func (c *csStateWatcher) SyncOnce(ctx context.Context, key controllerutils.HCPClusterKey) error {
	if !c.nextSyncChecker.CanSync(ctx, key) {
		return nil
	}

	// Get the cluster from cosmos to retrieve the ClusterServiceID
	cluster, err := c.cosmosClient.HCPClusters(key.SubscriptionID, key.ResourceGroupName).Get(ctx, key.HCPClusterName)
	if database.IsResponseError(err, http.StatusNotFound) {
		// Cluster doesn't exist in cosmos, nothing to check
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to get cluster from cosmos: %w", err)
	}

	csID := cluster.ServiceProviderProperties.ClusterServiceID
	if len(csID.String()) == 0 {
		// No ClusterServiceID yet, cluster hasn't been registered with CS
		return nil
	}

	// Collect all issues (failed and pending items)

	// Check cluster state
	csStatus, err := c.csClient.GetClusterStatus(ctx, csID)
	if err != nil {
		return utils.TrackError(err)
	}

	clusterState := csStatus.State()
	var statusErr error
	switch clusterState {
	case arohcpv1alpha1.ClusterStateError:
		msg := fmt.Sprintf("cluster: state=%s", clusterState)
		if desc := csStatus.Description(); desc != "" {
			msg = fmt.Sprintf("cluster: state=%s, description=%s", clusterState, desc)
		}
		if errCode := csStatus.ProvisionErrorCode(); errCode != "" {
			msg = fmt.Sprintf("%s, errorCode=%s", msg, errCode)
		}
		if errMsg := csStatus.ProvisionErrorMessage(); errMsg != "" {
			msg = fmt.Sprintf("%s, errorMessage=%s", msg, errMsg)
		}
		statusErr = fmt.Errorf("%s", msg)
	case arohcpv1alpha1.ClusterStatePending, arohcpv1alpha1.ClusterStateValidating:
		statusErr = fmt.Errorf("cluster: state=%s", clusterState)
		if desc := csStatus.Description(); desc != "" {
			statusErr = fmt.Errorf("cluster: state=%s, description=%s", clusterState, desc)
		}
	}

	return statusErr
}

func (c *csStateWatcher) CooldownChecker() controllerutils.CooldownChecker {
	return c.cooldownChecker
}
