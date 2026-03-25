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

package e2e

import (
	"context"
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	azcorearm "github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"k8s.io/apimachinery/pkg/util/rand"

	"github.com/Azure/ARO-HCP/test/util/framework"
	"github.com/Azure/ARO-HCP/test/util/labels"
)

var _ = Describe("Customer", func() {
	It("should be able to forward control plane logs to a storage account via shoebox diagnostic settings",
		labels.RequireNothing,
		labels.Medium,
		labels.Positive,
		labels.StageAndProdOnly,
		func(ctx context.Context) {
			const (
				customerNetworkSecurityGroupName = "customer-nsg-name"
				customerVnetName                 = "customer-vnet-name"
				customerVnetSubnetName           = "customer-vnet-subnet1"
				customerClusterName              = "shoebox-hcp-cluster"
				diagnosticSettingName            = "shoebox-diag-setting"
			)

			logCategories := []string{
				"kube-apiserver",
				"kube-audit",
				"kube-audit-admin",
				"kube-controller-manager",
				"kube-scheduler",
				"cloud-controller-manager",
				"csi-azuredisk-controller",
				"csi-azurefile-controller",
				"csi-snapshot-controller",
			}

			tc := framework.NewTestContext()

			if tc.UsePooledIdentities() {
				err := tc.AssignIdentityContainers(ctx, 1, 60*time.Second)
				Expect(err).NotTo(HaveOccurred())
			}

			By("creating a resource group")
			resourceGroup, err := tc.NewResourceGroup(ctx, "shoebox-cluster", tc.Location())
			Expect(err).NotTo(HaveOccurred())

			By("creating cluster parameters")
			clusterParams := framework.NewDefaultClusterParams()
			clusterParams.ClusterName = customerClusterName
			managedResourceGroupName := framework.SuffixName(*resourceGroup.Name, "-managed", 64)
			clusterParams.ManagedResourceGroupName = managedResourceGroupName

			By("creating customer resources")
			clusterParams, err = tc.CreateClusterCustomerResources(ctx,
				resourceGroup,
				clusterParams,
				map[string]any{
					"customerNsgName":        customerNetworkSecurityGroupName,
					"customerVnetName":       customerVnetName,
					"customerVnetSubnetName": customerVnetSubnetName,
				},
				TestArtifactsFS,
				framework.RBACScopeResourceGroup,
			)
			Expect(err).NotTo(HaveOccurred())

			By("creating the HCP cluster")
			err = tc.CreateHCPClusterFromParam(
				ctx,
				GinkgoLogr,
				*resourceGroup.Name,
				clusterParams,
				45*time.Minute,
			)
			Expect(err).NotTo(HaveOccurred())

			subscriptionID, err := tc.SubscriptionID(ctx)
			Expect(err).NotTo(HaveOccurred())

			creds, err := tc.AzureCredential()
			Expect(err).NotTo(HaveOccurred())

			By("creating a storage account for shoebox logs")
			storageAccountName := "shoebox" + rand.String(6)

			storageClient, err := armstorage.NewAccountsClient(subscriptionID, creds, nil)
			Expect(err).NotTo(HaveOccurred())

			storagePoller, err := storageClient.BeginCreate(ctx, *resourceGroup.Name, storageAccountName, armstorage.AccountCreateParameters{
				Kind:     to.Ptr(armstorage.KindStorageV2),
				Location: to.Ptr(tc.Location()),
				SKU: &armstorage.SKU{
					Name: to.Ptr(armstorage.SKUNameStandardLRS),
				},
			}, nil)
			Expect(err).NotTo(HaveOccurred())

			storageAccount, err := storagePoller.PollUntilDone(ctx, nil)
			Expect(err).NotTo(HaveOccurred())
			GinkgoLogr.Info("storage account created", "name", storageAccountName, "id", *storageAccount.ID)

			By("enabling diagnostic settings on the HCP cluster")
			clusterResourceID := fmt.Sprintf(
				"/subscriptions/%s/resourceGroups/%s/providers/Microsoft.RedHatOpenShift/hcpOpenShiftClusters/%s",
				subscriptionID, *resourceGroup.Name, customerClusterName,
			)

			logSettings := make([]*armmonitor.LogSettings, 0, len(logCategories))
			for _, category := range logCategories {
				logSettings = append(logSettings, &armmonitor.LogSettings{
					Category: to.Ptr(category),
					Enabled:  to.Ptr(true),
				})
			}

			diagnosticsClient, err := armmonitor.NewDiagnosticSettingsClient(creds, &azcorearm.ClientOptions{})
			Expect(err).NotTo(HaveOccurred())

			_, err = diagnosticsClient.CreateOrUpdate(ctx, clusterResourceID, diagnosticSettingName, armmonitor.DiagnosticSettingsResource{
				Properties: &armmonitor.DiagnosticSettings{
					StorageAccountID: storageAccount.ID,
					Logs:             logSettings,
				},
			}, nil)
			Expect(err).NotTo(HaveOccurred())
			GinkgoLogr.Info("diagnostic setting created", "name", diagnosticSettingName)

			By("waiting for log containers to appear in the storage account")
			blobContainersClient, err := armstorage.NewBlobContainersClient(subscriptionID, creds, nil)
			Expect(err).NotTo(HaveOccurred())

			// Logs take ~35-40 minutes to appear. Poll for up to 45 minutes.
			Eventually(func() ([]string, error) {
				return listInsightsContainers(ctx, blobContainersClient, *resourceGroup.Name, storageAccountName)
			}, 45*time.Minute, 60*time.Second).ShouldNot(BeEmpty(),
				"expected at least one insights-logs-* blob container in storage account %s", storageAccountName,
			)

			By("verifying that log containers exist for expected categories")
			containers, err := listInsightsContainers(ctx, blobContainersClient, *resourceGroup.Name, storageAccountName)
			Expect(err).NotTo(HaveOccurred())
			GinkgoLogr.Info("found log containers", "containers", containers)
			Expect(len(containers)).To(BeNumerically(">", 0),
				"expected at least one insights-logs-* container, got none",
			)
		})
})

// listInsightsContainers returns the names of blob containers in the storage account
// that start with "insights-logs-", which is the prefix Azure Monitor uses for diagnostic logs.
func listInsightsContainers(ctx context.Context, client *armstorage.BlobContainersClient, resourceGroupName, storageAccountName string) ([]string, error) {
	var controlPlaneContainers []string
	pager := client.NewListPager(resourceGroupName, storageAccountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list blob containers: %w", err)
		}
		for _, container := range page.Value {
			if container.Name != nil && strings.HasPrefix(*container.Name, "insights-logs-") {
				controlPlaneContainers = append(controlPlaneContainers, *container.Name)
			}
		}
	}
	return controlPlaneContainers, nil
}
