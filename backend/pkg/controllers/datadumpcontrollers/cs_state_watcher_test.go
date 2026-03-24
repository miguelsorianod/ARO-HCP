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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	azcorearm "github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"

	arohcpv1alpha1 "github.com/openshift-online/ocm-sdk-go/arohcp/v1alpha1"

	"github.com/Azure/ARO-HCP/backend/pkg/controllers/controllerutils"
	"github.com/Azure/ARO-HCP/internal/api"
	"github.com/Azure/ARO-HCP/internal/api/arm"
	"github.com/Azure/ARO-HCP/internal/databasetesting"
	"github.com/Azure/ARO-HCP/internal/ocm"
)

func TestCSStateWatcher_SyncOnce(t *testing.T) {
	tests := []struct {
		name             string
		createCluster    bool
		setupCSClient    func(*ocm.MockClusterServiceClientSpec, api.InternalID)
		wantErr          bool
		wantErrSubstring string
	}{
		{
			name:          "cluster not found in DB returns nil",
			createCluster: false,
			wantErr:       false,
		},
		{
			name:          "healthy cluster returns nil",
			createCluster: true,
			setupCSClient: func(mock *ocm.MockClusterServiceClientSpec, csID api.InternalID) {
				csStatus, _ := arohcpv1alpha1.NewClusterStatus().
					State(arohcpv1alpha1.ClusterStateReady).
					Build()
				mock.EXPECT().GetClusterStatus(gomock.Any(), csID).Return(csStatus, nil)
			},
			wantErr: false,
		},
		{
			name:          "failed cluster returns error with state and error code",
			createCluster: true,
			setupCSClient: func(mock *ocm.MockClusterServiceClientSpec, csID api.InternalID) {
				csStatus, _ := arohcpv1alpha1.NewClusterStatus().
					State(arohcpv1alpha1.ClusterStateError).
					Description("Provisioning failed").
					ProvisionErrorCode("OCM4001").
					ProvisionErrorMessage("Inflight checks failed").
					Build()
				mock.EXPECT().GetClusterStatus(gomock.Any(), csID).Return(csStatus, nil)
			},
			wantErr:          true,
			wantErrSubstring: "cluster: state=error",
		},
		{
			name:          "pending cluster returns error with state",
			createCluster: true,
			setupCSClient: func(mock *ocm.MockClusterServiceClientSpec, csID api.InternalID) {
				csStatus, _ := arohcpv1alpha1.NewClusterStatus().
					State(arohcpv1alpha1.ClusterStatePending).
					Description("Waiting for resources").
					Build()
				mock.EXPECT().GetClusterStatus(gomock.Any(), csID).Return(csStatus, nil)
			},
			wantErr:          true,
			wantErrSubstring: "cluster: state=pending",
		},
		{
			name:          "CS client error returns error",
			createCluster: true,
			setupCSClient: func(mock *ocm.MockClusterServiceClientSpec, csID api.InternalID) {
				mock.EXPECT().GetClusterStatus(gomock.Any(), csID).Return(nil, fmt.Errorf("connection error"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			ctx := context.Background()

			mockDBClient := databasetesting.NewMockDBClient()
			mockCSClient := ocm.NewMockClusterServiceClientSpec(ctrl)

			syncer := &csStateWatcher{
				cooldownChecker: &alwaysSyncCooldownChecker{},
				cosmosClient:    mockDBClient,
				csClient:        mockCSClient,
				nextSyncChecker: &alwaysSyncCooldownChecker{},
			}

			key := controllerutils.HCPClusterKey{
				SubscriptionID:    "test-sub",
				ResourceGroupName: "test-rg",
				HCPClusterName:    "test-cluster",
			}

			csID := api.Must(api.NewInternalID("/api/aro_hcp/v1alpha1/clusters/11111111111111111111111111111111"))

			if tt.createCluster {
				clusterResourceID := api.Must(azcorearm.ParseResourceID("/subscriptions/test-sub/resourceGroups/test-rg/providers/Microsoft.RedHatOpenShift/hcpOpenShiftClusters/test-cluster"))
				cluster := &api.HCPOpenShiftCluster{
					TrackedResource: arm.TrackedResource{
						Resource: arm.Resource{ID: clusterResourceID},
					},
					ServiceProviderProperties: api.HCPOpenShiftClusterServiceProviderProperties{
						ClusterServiceID: csID,
					},
				}

				clustersCRUD := mockDBClient.HCPClusters(key.SubscriptionID, key.ResourceGroupName)
				_, err := clustersCRUD.Create(ctx, cluster, nil)
				require.NoError(t, err)
			}

			if tt.setupCSClient != nil {
				tt.setupCSClient(mockCSClient, csID)
			}

			err := syncer.SyncOnce(ctx, key)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantErrSubstring != "" {
					assert.Contains(t, err.Error(), tt.wantErrSubstring)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
