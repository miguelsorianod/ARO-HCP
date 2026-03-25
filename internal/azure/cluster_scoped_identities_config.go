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

package azure

import (
	"fmt"

	"github.com/blang/semver/v4"

	azcorearm "github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"

	"github.com/Azure/ARO-HCP/internal/api"
)

// ClusterOperatorIdentifier is the identifier of a cluster operator
type ClusterOperatorIdentifier string

// The set of cluster operators recognized by the service.
// operator identifiers that are not defined here are considered unknown operators.
const (
	ClusterOperatorIdentifierClusterAPIAzure        ClusterOperatorIdentifier = "cluster-api-azure"
	ClusterOperatorIdentifierControlPlane           ClusterOperatorIdentifier = "control-plane"
	ClusterOperatorIdentifierCloudControllerManager ClusterOperatorIdentifier = "cloud-controller-manager"
	ClusterOperatorIdentifierIngress                ClusterOperatorIdentifier = "ingress"
	ClusterOperatorIdentifierDiskCSIDriver          ClusterOperatorIdentifier = "disk-csi-driver"
	ClusterOperatorIdentifierFileCSIDriver          ClusterOperatorIdentifier = "file-csi-driver"
	ClusterOperatorIdentifierImageRegistry          ClusterOperatorIdentifier = "image-registry"
	ClusterOperatorIdentifierCloudNetworkConfig     ClusterOperatorIdentifier = "cloud-network-config"
	ClusterOperatorIdentifierKMS                    ClusterOperatorIdentifier = "kms"
)

// ClusterScopedIdentitiesConfig is the configuration for all cluster scoped identities.
// This configuration contains the control plane and data plane operator identities
// that are recognized by the service, as well as information about the service managed identity.
type ClusterScopedIdentitiesConfig struct {
	// ControlPlaneOperatorsIdentities is the configuration of the control plane operators identities.
	// This configuration contains the control plane operator identities that are recognized by the service.
	ControlPlaneOperatorsIdentities ControlPlaneOperatorsIdentities
	// DataPlaneOperatorsIdentities is the configuration for the data plane operators identities.
	// This configuration contains the data plane operator identities that are recognized by the service.
	DataPlaneOperatorsIdentities DataPlaneOperatorsIdentities
	// ServiceManagedIdentity is the configuration for the service managed identity.
	// This configuration contains the information about the service managed identity.
	ServiceManagedIdentity *ServiceManagedIdentity
}

// ControlPlaneOperatorsIdentities is a map of control plane operator identities.
type ControlPlaneOperatorsIdentities map[ClusterOperatorIdentifier]*ControlPlaneOperatorIdentity

// DataPlaneOperatorsIdentities is a map of data plane operator identities.
type DataPlaneOperatorsIdentities map[ClusterOperatorIdentifier]*DataPlaneOperatorIdentity

// GetAlwaysRequiredControlPlaneOperators retrieves the control plane operators identities that are always required
// for the given version.
// The meaning of always required for a given version is that the operator identity is always
// required for the given version, independently on the configuration of the cluster and its derivated resources.
// Pre-release and build metadata from version are excluded from the comparison.
func (c *ClusterScopedIdentitiesConfig) AlwaysRequiredControlPlaneOperators(version *semver.Version) ControlPlaneOperatorsIdentities {
	var alwaysRequiredControlPlaneOperators = make(ControlPlaneOperatorsIdentities)
	for _, controlPlaneOperator := range c.ControlPlaneOperatorsIdentities {
		required := controlPlaneOperator.isAlwaysRequiredForOpenshiftVersion(version)
		if required {
			alwaysRequiredControlPlaneOperators[controlPlaneOperator.ClusterOperatorIdentifier] = controlPlaneOperator
		}
	}
	return alwaysRequiredControlPlaneOperators
}

// AlwaysRequiredDataPlaneOperators retrieves the data plane operators identities that are always required
// for the given version.
// The meaning of always required for a given version is that the operator identity is always
// required for the given version, independently on the configuration of the cluster and its derivated resources.
// Pre-release and build metadata from version are excluded from the comparison.
func (c *ClusterScopedIdentitiesConfig) AlwaysRequiredDataPlaneOperators(version *semver.Version) DataPlaneOperatorsIdentities {
	var alwaysRequiredDataPlaneOperators = make(DataPlaneOperatorsIdentities)
	for _, dataPlaneOperator := range c.DataPlaneOperatorsIdentities {
		required := dataPlaneOperator.isAlwaysRequiredForOpenshiftVersion(version)
		if required {
			alwaysRequiredDataPlaneOperators[dataPlaneOperator.ClusterOperatorIdentifier] = dataPlaneOperator
		}
	}
	return alwaysRequiredDataPlaneOperators
}

// RoleDefinitionConfigSetName is the name of a role definition config set.
// It is used to select the appropriate set of role definitions. This allows us
// to have different role definitions depending on how to service is deployed.
type RoleDefinitionConfigSetName string

const (
	// RoleDefinitionConfigSetNameDev is the name of the "dev" role definition config set.
	RoleDefinitionConfigSetNameDev RoleDefinitionConfigSetName = "dev"
	// RoleDefinitionConfigSetNamePublic is the name of the "public" role definition config set.
	RoleDefinitionConfigSetNamePublic RoleDefinitionConfigSetName = "public"
)

// newRoleDefinitionConfigSets creates a new RoleDefinitionConfigSets containing
// all the role definition config sets for all existing RoleDefinitionConfigSetName defined values.
func newRoleDefinitionConfigSets() *roleDefinitionConfigSets {
	roleDefinitionConfigSets := &roleDefinitionConfigSets{}
	roleDefinitionConfigSets.DevRoleDefinitionConfigSet = buildDevRoleDefinitionConfigSet()
	roleDefinitionConfigSets.PublicRoleDefinitionConfigSet = buildPublicRoleDefinitionConfigSet()

	return roleDefinitionConfigSets
}

// buildPublicRoleDefinitionConfigSet builds the public role definition config set corresponding to
// the role definition config set RoleDefinitionConfigSetNamePublic.
func buildPublicRoleDefinitionConfigSet() *RoleDefinitionConfigSet {
	publicRoleDefinitionConfigSet := &RoleDefinitionConfigSet{
		ControlPlaneOperatorsIdentitiesRoleDefinitions: make(ControlPlaneOperatorsIdentitiesRoleDefinitions),
		DataPlaneOperatorsIdentitiesRoleDefinitions:    make(DataPlaneOperatorsIdentitiesRoleDefinitions),
		ServiceManagedIdentityRoleDefinitions:          ServiceManagedIdentityRoleDefinitions{},
	}

	publicRoleDefinitionConfigSet.ControlPlaneOperatorsIdentitiesRoleDefinitions[ClusterOperatorIdentifierClusterAPIAzure] = []*ClusterScopedIdentityRoleDefinition{
		{
			DescriptiveName: "Azure Red Hat OpenShift Hosted Control Planes Cluster API Provider",
			ResourceID:      api.Must(azcorearm.ParseResourceID("/providers/Microsoft.Authorization/roleDefinitions/88366f10-ed47-4cc0-9fab-c8a06148393e")),
		},
	}
	publicRoleDefinitionConfigSet.ControlPlaneOperatorsIdentitiesRoleDefinitions[ClusterOperatorIdentifierControlPlane] = []*ClusterScopedIdentityRoleDefinition{
		{
			DescriptiveName: "Azure Red Hat OpenShift Hosted Control Planes Control Plane Operator",
			ResourceID:      api.Must(azcorearm.ParseResourceID("/providers/Microsoft.Authorization/roleDefinitions/fc0c873f-45e9-4d0d-a7d1-585aab30c6ed")),
		},
	}
	publicRoleDefinitionConfigSet.ControlPlaneOperatorsIdentitiesRoleDefinitions[ClusterOperatorIdentifierCloudControllerManager] = []*ClusterScopedIdentityRoleDefinition{
		{
			DescriptiveName: "Azure Red Hat OpenShift Cloud Controller Manager",
			ResourceID:      api.Must(azcorearm.ParseResourceID("/providers/Microsoft.Authorization/roleDefinitions/a1f96423-95ce-4224-ab27-4e3dc72facd4")),
		},
	}
	publicRoleDefinitionConfigSet.ControlPlaneOperatorsIdentitiesRoleDefinitions[ClusterOperatorIdentifierIngress] = []*ClusterScopedIdentityRoleDefinition{
		{
			DescriptiveName: "Azure Red Hat OpenShift Cluster Ingress Operator",
			ResourceID:      api.Must(azcorearm.ParseResourceID("/providers/Microsoft.Authorization/roleDefinitions/0336e1d3-7a87-462b-b6db-342b63f7802c")),
		},
	}
	publicRoleDefinitionConfigSet.ControlPlaneOperatorsIdentitiesRoleDefinitions[ClusterOperatorIdentifierDiskCSIDriver] = []*ClusterScopedIdentityRoleDefinition{
		{
			DescriptiveName: "Azure Red Hat OpenShift Disk Storage Operator",
			ResourceID:      api.Must(azcorearm.ParseResourceID("/providers/Microsoft.Authorization/roleDefinitions/5b7237c5-45e1-49d6-bc18-a1f62f400748")),
		},
	}
	publicRoleDefinitionConfigSet.ControlPlaneOperatorsIdentitiesRoleDefinitions[ClusterOperatorIdentifierFileCSIDriver] = []*ClusterScopedIdentityRoleDefinition{
		{
			DescriptiveName: "Azure Red Hat OpenShift File Storage Operator",
			ResourceID:      api.Must(azcorearm.ParseResourceID("/providers/Microsoft.Authorization/roleDefinitions/0d7aedc0-15fd-4a67-a412-efad370c947e")),
		},
	}
	publicRoleDefinitionConfigSet.ControlPlaneOperatorsIdentitiesRoleDefinitions[ClusterOperatorIdentifierImageRegistry] = []*ClusterScopedIdentityRoleDefinition{
		{
			DescriptiveName: "Azure Red Hat OpenShift Image Registry Operator",
			ResourceID:      api.Must(azcorearm.ParseResourceID("/providers/Microsoft.Authorization/roleDefinitions/8b32b316-c2f5-4ddf-b05b-83dacd2d08b5")),
		},
	}
	publicRoleDefinitionConfigSet.ControlPlaneOperatorsIdentitiesRoleDefinitions[ClusterOperatorIdentifierCloudNetworkConfig] = []*ClusterScopedIdentityRoleDefinition{
		{
			DescriptiveName: "Azure Red Hat OpenShift Network Operator",
			ResourceID:      api.Must(azcorearm.ParseResourceID("/providers/Microsoft.Authorization/roleDefinitions/be7a6435-15ae-4171-8f30-4a343eff9e8f")),
		},
	}
	publicRoleDefinitionConfigSet.ControlPlaneOperatorsIdentitiesRoleDefinitions[ClusterOperatorIdentifierKMS] = []*ClusterScopedIdentityRoleDefinition{
		{
			DescriptiveName: "Key Vault Crypto User",
			ResourceID:      api.Must(azcorearm.ParseResourceID("/providers/Microsoft.Authorization/roleDefinitions/12338af0-0e69-4776-bea7-57ae8d297424")),
		},
	}

	publicRoleDefinitionConfigSet.DataPlaneOperatorsIdentitiesRoleDefinitions[ClusterOperatorIdentifierDiskCSIDriver] = []*ClusterScopedIdentityRoleDefinition{
		{
			DescriptiveName: "Azure Red Hat OpenShift Disk Storage Operator",
			ResourceID:      api.Must(azcorearm.ParseResourceID("/providers/Microsoft.Authorization/roleDefinitions/5b7237c5-45e1-49d6-bc18-a1f62f400748")),
		},
	}

	publicRoleDefinitionConfigSet.DataPlaneOperatorsIdentitiesRoleDefinitions[ClusterOperatorIdentifierImageRegistry] = []*ClusterScopedIdentityRoleDefinition{
		{
			DescriptiveName: "Azure Red Hat OpenShift Image Registry Operator",
			ResourceID:      api.Must(azcorearm.ParseResourceID("/providers/Microsoft.Authorization/roleDefinitions/8b32b316-c2f5-4ddf-b05b-83dacd2d08b5")),
		},
	}
	publicRoleDefinitionConfigSet.DataPlaneOperatorsIdentitiesRoleDefinitions[ClusterOperatorIdentifierFileCSIDriver] = []*ClusterScopedIdentityRoleDefinition{
		{
			DescriptiveName: "Azure Red Hat OpenShift File Storage Operator",
			ResourceID:      api.Must(azcorearm.ParseResourceID("/providers/Microsoft.Authorization/roleDefinitions/0d7aedc0-15fd-4a67-a412-efad370c947e")),
		},
	}

	publicRoleDefinitionConfigSet.ServiceManagedIdentityRoleDefinitions = ServiceManagedIdentityRoleDefinitions{
		&ClusterScopedIdentityRoleDefinition{
			DescriptiveName: "Azure Red Hat OpenShift Hosted Control Planes Service Managed Identity",
			ResourceID:      api.Must(azcorearm.ParseResourceID("/providers/Microsoft.Authorization/roleDefinitions/c0ff367d-66d8-445e-917c-583feb0ef0d4")),
		},
	}

	return publicRoleDefinitionConfigSet
}

// buildDevRoleDefinitionConfigSet builds the dev role definition config set corresponding to
// the role definition config set RoleDefinitionConfigSetNameDev.
func buildDevRoleDefinitionConfigSet() *RoleDefinitionConfigSet {
	devRoleDefinitionConfigSet := &RoleDefinitionConfigSet{
		ControlPlaneOperatorsIdentitiesRoleDefinitions: make(ControlPlaneOperatorsIdentitiesRoleDefinitions),
		DataPlaneOperatorsIdentitiesRoleDefinitions:    make(DataPlaneOperatorsIdentitiesRoleDefinitions),
		ServiceManagedIdentityRoleDefinitions:          ServiceManagedIdentityRoleDefinitions{},
	}

	devRoleDefinitionConfigSet.ControlPlaneOperatorsIdentitiesRoleDefinitions[ClusterOperatorIdentifierClusterAPIAzure] = []*ClusterScopedIdentityRoleDefinition{
		{
			DescriptiveName: "Azure Red Hat OpenShift Hosted Control Planes Cluster API Provider",
			ResourceID:      api.Must(azcorearm.ParseResourceID("/providers/Microsoft.Authorization/roleDefinitions/88366f10-ed47-4cc0-9fab-c8a06148393e")),
		},
	}
	devRoleDefinitionConfigSet.ControlPlaneOperatorsIdentitiesRoleDefinitions[ClusterOperatorIdentifierControlPlane] = []*ClusterScopedIdentityRoleDefinition{
		{
			DescriptiveName: "Azure Red Hat OpenShift Hosted Control Planes Control Plane Operator",
			ResourceID:      api.Must(azcorearm.ParseResourceID("/providers/Microsoft.Authorization/roleDefinitions/fc0c873f-45e9-4d0d-a7d1-585aab30c6ed")),
		},
	}
	devRoleDefinitionConfigSet.ControlPlaneOperatorsIdentitiesRoleDefinitions[ClusterOperatorIdentifierCloudControllerManager] = []*ClusterScopedIdentityRoleDefinition{
		{
			DescriptiveName: "Azure Red Hat OpenShift Cloud Controller Manager",
			ResourceID:      api.Must(azcorearm.ParseResourceID("/providers/Microsoft.Authorization/roleDefinitions/a1f96423-95ce-4224-ab27-4e3dc72facd4")),
		},
	}
	devRoleDefinitionConfigSet.ControlPlaneOperatorsIdentitiesRoleDefinitions[ClusterOperatorIdentifierIngress] = []*ClusterScopedIdentityRoleDefinition{
		{
			DescriptiveName: "Azure Red Hat OpenShift Cluster Ingress Operator",
			ResourceID:      api.Must(azcorearm.ParseResourceID("/providers/Microsoft.Authorization/roleDefinitions/0336e1d3-7a87-462b-b6db-342b63f7802c")),
		},
	}
	devRoleDefinitionConfigSet.ControlPlaneOperatorsIdentitiesRoleDefinitions[ClusterOperatorIdentifierDiskCSIDriver] = []*ClusterScopedIdentityRoleDefinition{
		{
			DescriptiveName: "Azure Red Hat OpenShift Disk Storage Operator",
			ResourceID:      api.Must(azcorearm.ParseResourceID("/providers/Microsoft.Authorization/roleDefinitions/5b7237c5-45e1-49d6-bc18-a1f62f400748")),
		},
	}
	devRoleDefinitionConfigSet.ControlPlaneOperatorsIdentitiesRoleDefinitions[ClusterOperatorIdentifierFileCSIDriver] = []*ClusterScopedIdentityRoleDefinition{
		{
			DescriptiveName: "Azure Red Hat OpenShift File Storage Operator",
			ResourceID:      api.Must(azcorearm.ParseResourceID("/providers/Microsoft.Authorization/roleDefinitions/0d7aedc0-15fd-4a67-a412-efad370c947e")),
		},
	}
	devRoleDefinitionConfigSet.ControlPlaneOperatorsIdentitiesRoleDefinitions[ClusterOperatorIdentifierImageRegistry] = []*ClusterScopedIdentityRoleDefinition{
		{
			DescriptiveName: "Azure Red Hat OpenShift Image Registry Operator",
			ResourceID:      api.Must(azcorearm.ParseResourceID("/providers/Microsoft.Authorization/roleDefinitions/8b32b316-c2f5-4ddf-b05b-83dacd2d08b5")),
		},
	}
	devRoleDefinitionConfigSet.ControlPlaneOperatorsIdentitiesRoleDefinitions[ClusterOperatorIdentifierCloudNetworkConfig] = []*ClusterScopedIdentityRoleDefinition{
		{
			DescriptiveName: "Azure Red Hat OpenShift Network Operator",
			ResourceID:      api.Must(azcorearm.ParseResourceID("/providers/Microsoft.Authorization/roleDefinitions/be7a6435-15ae-4171-8f30-4a343eff9e8f")),
		},
	}
	devRoleDefinitionConfigSet.ControlPlaneOperatorsIdentitiesRoleDefinitions[ClusterOperatorIdentifierKMS] = []*ClusterScopedIdentityRoleDefinition{
		{
			DescriptiveName: "Key Vault Crypto User",
			ResourceID:      api.Must(azcorearm.ParseResourceID("/providers/Microsoft.Authorization/roleDefinitions/12338af0-0e69-4776-bea7-57ae8d297424")),
		},
	}

	devRoleDefinitionConfigSet.DataPlaneOperatorsIdentitiesRoleDefinitions[ClusterOperatorIdentifierDiskCSIDriver] = []*ClusterScopedIdentityRoleDefinition{
		{
			DescriptiveName: "Azure Red Hat OpenShift Disk Storage Operator",
			ResourceID:      api.Must(azcorearm.ParseResourceID("/providers/Microsoft.Authorization/roleDefinitions/5b7237c5-45e1-49d6-bc18-a1f62f400748")),
		},
	}

	devRoleDefinitionConfigSet.DataPlaneOperatorsIdentitiesRoleDefinitions[ClusterOperatorIdentifierImageRegistry] = []*ClusterScopedIdentityRoleDefinition{
		{
			DescriptiveName: "Azure Red Hat OpenShift Image Registry Operator",
			ResourceID:      api.Must(azcorearm.ParseResourceID("/providers/Microsoft.Authorization/roleDefinitions/8b32b316-c2f5-4ddf-b05b-83dacd2d08b5")),
		},
	}
	devRoleDefinitionConfigSet.DataPlaneOperatorsIdentitiesRoleDefinitions[ClusterOperatorIdentifierFileCSIDriver] = []*ClusterScopedIdentityRoleDefinition{
		{
			DescriptiveName: "Azure Red Hat OpenShift File Storage Operator",
			ResourceID:      api.Must(azcorearm.ParseResourceID("/providers/Microsoft.Authorization/roleDefinitions/0d7aedc0-15fd-4a67-a412-efad370c947e")),
		},
	}

	devRoleDefinitionConfigSet.ServiceManagedIdentityRoleDefinitions = ServiceManagedIdentityRoleDefinitions{
		&ClusterScopedIdentityRoleDefinition{
			DescriptiveName: "Azure Red Hat OpenShift Hosted Control Planes Service Managed Identity",
			ResourceID:      api.Must(azcorearm.ParseResourceID("/providers/Microsoft.Authorization/roleDefinitions/c0ff367d-66d8-445e-917c-583feb0ef0d4")),
		},
	}

	return devRoleDefinitionConfigSet
}

// NewClusterScopedIdentitiesConfig creates a new ClusterScopedIdentitiesConfig based on the setName RoleDefinitionConfigSetName.
func NewClusterScopedIdentitiesConfig(setName RoleDefinitionConfigSetName) *ClusterScopedIdentitiesConfig {
	roleDefinitionConfigSets := newRoleDefinitionConfigSets()
	controlPlaneOperatorsIdentitiesRoleDefinitions := roleDefinitionConfigSets.getControlPlaneOperatorsIdentitiesRoleDefinitions(setName)
	dataPlaneOperatorsIdentitiesRoleDefinitions := roleDefinitionConfigSets.getDataPlaneOperatorsIdentitiesRoleDefinitions(setName)
	serviceManagedIdentityRoleDefinitions := roleDefinitionConfigSets.getServiceManagedIdentityRoleDefinitions(setName)

	controlPlaneOperatorsIdentities := make(map[ClusterOperatorIdentifier]*ControlPlaneOperatorIdentity)

	controlPlaneOperatorsIdentities[ClusterOperatorIdentifierClusterAPIAzure] = &ControlPlaneOperatorIdentity{
		BaseClusterScopedOperatorIdentity: BaseClusterScopedOperatorIdentity{
			ClusterOperatorIdentifier: ClusterOperatorIdentifierClusterAPIAzure,
			MinVersionInclusive:       to.Ptr(api.Must(semver.ParseTolerant("4.19"))),
			Requirement:               &IdentityRequirement{Type: IdentityRequirementTypeAlways},
			BaseClusterScopedIdentity: BaseClusterScopedIdentity{
				RoleDefinitions: controlPlaneOperatorsIdentitiesRoleDefinitions[ClusterOperatorIdentifierClusterAPIAzure],
			},
		},
	}

	controlPlaneOperatorsIdentities[ClusterOperatorIdentifierControlPlane] = &ControlPlaneOperatorIdentity{
		BaseClusterScopedOperatorIdentity: BaseClusterScopedOperatorIdentity{
			ClusterOperatorIdentifier: ClusterOperatorIdentifierControlPlane,
			MinVersionInclusive:       to.Ptr(api.Must(semver.ParseTolerant("4.19"))),
			Requirement:               &IdentityRequirement{Type: IdentityRequirementTypeAlways},
			BaseClusterScopedIdentity: BaseClusterScopedIdentity{
				RoleDefinitions: controlPlaneOperatorsIdentitiesRoleDefinitions[ClusterOperatorIdentifierControlPlane],
			},
		},
	}
	controlPlaneOperatorsIdentities[ClusterOperatorIdentifierCloudControllerManager] = &ControlPlaneOperatorIdentity{
		BaseClusterScopedOperatorIdentity: BaseClusterScopedOperatorIdentity{
			ClusterOperatorIdentifier: ClusterOperatorIdentifierCloudControllerManager,
			MinVersionInclusive:       to.Ptr(api.Must(semver.ParseTolerant("4.19"))),
			Requirement:               &IdentityRequirement{Type: IdentityRequirementTypeAlways},
			BaseClusterScopedIdentity: BaseClusterScopedIdentity{
				RoleDefinitions: controlPlaneOperatorsIdentitiesRoleDefinitions[ClusterOperatorIdentifierCloudControllerManager],
			},
		},
	}
	controlPlaneOperatorsIdentities[ClusterOperatorIdentifierIngress] = &ControlPlaneOperatorIdentity{
		BaseClusterScopedOperatorIdentity: BaseClusterScopedOperatorIdentity{
			ClusterOperatorIdentifier: ClusterOperatorIdentifierIngress,
			MinVersionInclusive:       to.Ptr(api.Must(semver.ParseTolerant("4.19"))),
			Requirement:               &IdentityRequirement{Type: IdentityRequirementTypeAlways},
			BaseClusterScopedIdentity: BaseClusterScopedIdentity{
				RoleDefinitions: controlPlaneOperatorsIdentitiesRoleDefinitions[ClusterOperatorIdentifierIngress],
			},
		},
	}
	controlPlaneOperatorsIdentities[ClusterOperatorIdentifierDiskCSIDriver] = &ControlPlaneOperatorIdentity{
		BaseClusterScopedOperatorIdentity: BaseClusterScopedOperatorIdentity{
			ClusterOperatorIdentifier: ClusterOperatorIdentifierDiskCSIDriver,
			MinVersionInclusive:       to.Ptr(api.Must(semver.ParseTolerant("4.19"))),
			Requirement:               &IdentityRequirement{Type: IdentityRequirementTypeAlways},
			BaseClusterScopedIdentity: BaseClusterScopedIdentity{
				RoleDefinitions: controlPlaneOperatorsIdentitiesRoleDefinitions[ClusterOperatorIdentifierDiskCSIDriver],
			},
		},
	}
	controlPlaneOperatorsIdentities[ClusterOperatorIdentifierFileCSIDriver] = &ControlPlaneOperatorIdentity{
		BaseClusterScopedOperatorIdentity: BaseClusterScopedOperatorIdentity{
			ClusterOperatorIdentifier: ClusterOperatorIdentifierFileCSIDriver,
			MinVersionInclusive:       to.Ptr(api.Must(semver.ParseTolerant("4.19"))),
			Requirement:               &IdentityRequirement{Type: IdentityRequirementTypeAlways},
			BaseClusterScopedIdentity: BaseClusterScopedIdentity{
				RoleDefinitions: controlPlaneOperatorsIdentitiesRoleDefinitions[ClusterOperatorIdentifierFileCSIDriver],
			},
		},
	}
	controlPlaneOperatorsIdentities[ClusterOperatorIdentifierImageRegistry] = &ControlPlaneOperatorIdentity{
		BaseClusterScopedOperatorIdentity: BaseClusterScopedOperatorIdentity{
			ClusterOperatorIdentifier: ClusterOperatorIdentifierImageRegistry,
			MinVersionInclusive:       to.Ptr(api.Must(semver.ParseTolerant("4.19"))),
			Requirement:               &IdentityRequirement{Type: IdentityRequirementTypeAlways},
			BaseClusterScopedIdentity: BaseClusterScopedIdentity{
				RoleDefinitions: controlPlaneOperatorsIdentitiesRoleDefinitions[ClusterOperatorIdentifierImageRegistry],
			},
		},
	}
	controlPlaneOperatorsIdentities[ClusterOperatorIdentifierCloudNetworkConfig] = &ControlPlaneOperatorIdentity{
		BaseClusterScopedOperatorIdentity: BaseClusterScopedOperatorIdentity{
			ClusterOperatorIdentifier: ClusterOperatorIdentifierCloudNetworkConfig,
			MinVersionInclusive:       to.Ptr(api.Must(semver.ParseTolerant("4.19"))),
			Requirement:               &IdentityRequirement{Type: IdentityRequirementTypeAlways},
			BaseClusterScopedIdentity: BaseClusterScopedIdentity{
				RoleDefinitions: controlPlaneOperatorsIdentitiesRoleDefinitions[ClusterOperatorIdentifierCloudNetworkConfig],
			},
		},
	}
	controlPlaneOperatorsIdentities[ClusterOperatorIdentifierKMS] = &ControlPlaneOperatorIdentity{
		BaseClusterScopedOperatorIdentity: BaseClusterScopedOperatorIdentity{
			ClusterOperatorIdentifier: ClusterOperatorIdentifierKMS,
			MinVersionInclusive:       to.Ptr(api.Must(semver.ParseTolerant("4.19"))),
			Requirement:               &IdentityRequirement{Type: IdentityRequirementTypeOnEnablement},
			BaseClusterScopedIdentity: BaseClusterScopedIdentity{
				RoleDefinitions: controlPlaneOperatorsIdentitiesRoleDefinitions[ClusterOperatorIdentifierKMS],
			},
		},
	}

	dataPlaneOperatorsIdentities := make(map[ClusterOperatorIdentifier]*DataPlaneOperatorIdentity)
	dataPlaneOperatorsIdentities[ClusterOperatorIdentifierDiskCSIDriver] = &DataPlaneOperatorIdentity{
		BaseClusterScopedOperatorIdentity: BaseClusterScopedOperatorIdentity{
			ClusterOperatorIdentifier: ClusterOperatorIdentifierDiskCSIDriver,
			MinVersionInclusive:       to.Ptr(api.Must(semver.ParseTolerant("4.19"))),
			Requirement:               &IdentityRequirement{Type: IdentityRequirementTypeAlways},
			BaseClusterScopedIdentity: BaseClusterScopedIdentity{
				RoleDefinitions: dataPlaneOperatorsIdentitiesRoleDefinitions[ClusterOperatorIdentifierDiskCSIDriver],
			},
		},
		KubernetesServiceAccounts: []*KubernetesServiceAccount{
			{
				Name:      "azure-disk-csi-driver-operator",
				Namespace: "openshift-cluster-csi-drivers",
			},
			{
				Name:      "azure-disk-csi-driver-controller-sa",
				Namespace: "openshift-cluster-csi-drivers",
			},
		},
	}

	dataPlaneOperatorsIdentities[ClusterOperatorIdentifierImageRegistry] = &DataPlaneOperatorIdentity{
		BaseClusterScopedOperatorIdentity: BaseClusterScopedOperatorIdentity{
			ClusterOperatorIdentifier: ClusterOperatorIdentifierImageRegistry,
			MinVersionInclusive:       to.Ptr(api.Must(semver.ParseTolerant("4.19"))),
			Requirement:               &IdentityRequirement{Type: IdentityRequirementTypeAlways},
			BaseClusterScopedIdentity: BaseClusterScopedIdentity{
				RoleDefinitions: dataPlaneOperatorsIdentitiesRoleDefinitions[ClusterOperatorIdentifierImageRegistry],
			},
		},
		KubernetesServiceAccounts: []*KubernetesServiceAccount{
			{
				Name:      "cluster-image-registry-operator",
				Namespace: "openshift-image-registry",
			},
			{
				Name:      "registry",
				Namespace: "openshift-image-registry",
			},
		},
	}

	dataPlaneOperatorsIdentities[ClusterOperatorIdentifierFileCSIDriver] = &DataPlaneOperatorIdentity{
		BaseClusterScopedOperatorIdentity: BaseClusterScopedOperatorIdentity{
			ClusterOperatorIdentifier: ClusterOperatorIdentifierFileCSIDriver,
			MinVersionInclusive:       to.Ptr(api.Must(semver.ParseTolerant("4.19"))),
			Requirement:               &IdentityRequirement{Type: IdentityRequirementTypeAlways},
			BaseClusterScopedIdentity: BaseClusterScopedIdentity{
				RoleDefinitions: dataPlaneOperatorsIdentitiesRoleDefinitions[ClusterOperatorIdentifierFileCSIDriver],
			},
		},
		KubernetesServiceAccounts: []*KubernetesServiceAccount{
			{
				Name:      "azure-file-csi-driver-operator",
				Namespace: "openshift-cluster-csi-drivers",
			},
			{
				Name:      "azure-file-csi-driver-controller-sa",
				Namespace: "openshift-cluster-csi-drivers",
			},
			{
				Name:      "azure-file-csi-driver-node-sa",
				Namespace: "openshift-cluster-csi-drivers",
			},
		},
	}

	serviceManagedIdentity := &ServiceManagedIdentity{
		BaseClusterScopedIdentity: BaseClusterScopedIdentity{
			RoleDefinitions: serviceManagedIdentityRoleDefinitions,
		},
	}

	return &ClusterScopedIdentitiesConfig{
		ControlPlaneOperatorsIdentities: controlPlaneOperatorsIdentities,
		DataPlaneOperatorsIdentities:    dataPlaneOperatorsIdentities,
		ServiceManagedIdentity:          serviceManagedIdentity,
	}
}

// BaseClusterScopedIdentity is the base configuration for all cluster scoped identities.
type BaseClusterScopedIdentity struct {
	// RoleDefinitions is the list of Azure Role Definitions for the identity.
	RoleDefinitions []*ClusterScopedIdentityRoleDefinition
}

// ControlPlaneOperatorIdentity is the configuration for a control plane operator identity.
type ControlPlaneOperatorIdentity struct {
	// BaseClusterScopedOperatorIdentity is the base configuration for the control plane operator identity.
	BaseClusterScopedOperatorIdentity
}

// DataPlaneOperatorIdentity is the configuration for a data plane operator identity.
type DataPlaneOperatorIdentity struct {
	// BaseClusterScopedOperatorIdentity is the base configuration for the data plane operator identity.
	BaseClusterScopedOperatorIdentity
	// KubernetesServiceAccounts is the list of Kubernetes Service Accounts needed by the data plane operator.
	// This information is used to federate an Azure Managed Identity to a K8s Subject.
	KubernetesServiceAccounts []*KubernetesServiceAccount
}

// ServiceManagedIdentity is the configuration for the cluster scoped service managed identity.
type ServiceManagedIdentity struct {
	// BaseClusterScopedIdentity is the base configuration for the service managed identity.
	BaseClusterScopedIdentity
}

// RoleDefinitionsResourceIDs returns the resource IDs of the Azure Role Definitions associated to the identity.
func (b *BaseClusterScopedIdentity) RoleDefinitionsResourceIDs() []*azcorearm.ResourceID {
	var ids []*azcorearm.ResourceID
	for _, rd := range b.RoleDefinitions {
		if rd != nil && rd.ResourceID != nil {
			ids = append(ids, rd.ResourceID)
		}
	}
	return ids
}

// BaseClusterScopedOperatorIdentity is the base configuration for all cluster scoped identities
// that are used by cluster operators.
type BaseClusterScopedOperatorIdentity struct {
	// BaseClusterScopedIdentity is the base configuration for the cluster scoped operator identity.
	BaseClusterScopedIdentity
	// ClusterOperatorIdentifier is the identifier of the cluster operator.
	// Note: it is the same value as the key in the corresponding controlPlaneOperatorsIdentities or dataPlaneOperatorsIdentities map.
	// However, we set it here too so BaseOperatorIdentity can be used by itself and have the information contained within it.
	ClusterOperatorIdentifier ClusterOperatorIdentifier
	// MinVersionInclusive is the minimum OpenShift version supported by the identity, inclusive.
	// When not set (nil), it indicates that the cluster scoped operator identity is supported for all OpenShift versions,
	// or up to MaxVersionInclusive if MaxVersionInclusive is set.
	// A Pre-release version whose non pre-release part matches MinVersionInclusive is also considered within MinVersionInclusive.
	MinVersionInclusive *semver.Version
	// MaxVersionInclusive is the maximum OpenShift version supported by the identity, inclusive.
	// When not set (nil), it indicates that the cluster scoped operator identity is supported for all OpenShift versions,
	// or starting from MinVersionInclusive if MinVersionInclusive is set.
	// A Pre-release version whose non pre-release part matches MaxVersionInclusive is also considered within MaxVersionInclusive.
	MaxVersionInclusive *semver.Version
	// Requirement indicates the requirement for the cluster scoped operator identity for a successful installation
	// and/or update of a Cluster (within the VersionsRange constraints).
	Requirement *IdentityRequirement
}

// versionExcludingPrereleaseAndBuild returns a copy of v with prerelease and build metadata cleared so that
// semver range checks use only major.minor.patch (e.g. 4.19.0-rc.1 is treated like 4.19.0).
func versionExcludingPrereleaseAndBuild(v semver.Version) semver.Version {
	v.Pre = nil
	v.Build = nil
	return v
}

// IsSupportedForOpenshiftVersion returns true if the operator identity is supported for the given OpenShift version.
// An operator identity is supported for a given version if the version is within the range
// of versions defined by b.VersionsRange. Pre-release and build metadata from version are excluded from the comparison.
func (b *BaseClusterScopedOperatorIdentity) IsSupportedForOpenshiftVersion(version *semver.Version) bool {
	versionExclPrereleaseAndBuild := versionExcludingPrereleaseAndBuild(*version)

	// If no version constraints are defined, the operator identity is supported for all OpenShift versions.
	if b.MinVersionInclusive == nil && b.MaxVersionInclusive == nil {
		return true
	}

	// If the version is less than the minimum version, the operator identity is not supported.
	if b.MinVersionInclusive != nil && versionExclPrereleaseAndBuild.LT(*b.MinVersionInclusive) {
		return false
	}

	// If the version is greater than the maximum version, the operator identity is not supported.
	if b.MaxVersionInclusive != nil && versionExclPrereleaseAndBuild.GT(*b.MaxVersionInclusive) {
		return false
	}

	// If the version is within the range of versions defined by b.MinVersionInclusive and b.MaxVersionInclusive, the operator identity is supported.
	return true
}

// isAlwaysRequiredForOpenshiftVersion returns true if the operator identity is always required for the given OpenShift version.
// The meaning of always required for a given version is that the operator identity is always required for the given version, independently on
// the configuration of the cluster and its derivated resources.
// Pre-release and build metadata from version are excluded from the comparison.
func (b *BaseClusterScopedOperatorIdentity) isAlwaysRequiredForOpenshiftVersion(version *semver.Version) bool {
	if !b.isAlwaysRequired() {
		return false
	}

	return b.IsSupportedForOpenshiftVersion(version)
}

// isAlwaysRequired returns true if the identity is always required.
// The meaning of always required for a given version is that the operator identity is always required for the given version, independently on
// the configuration of the cluster and its derivated resources.
// This applies to the range of versions [b.MinVersionInclusive, b.MaxVersionInclusive] defined in b.
func (b *BaseClusterScopedOperatorIdentity) isAlwaysRequired() bool {
	return b.Requirement.Type == IdentityRequirementTypeAlways
}

// IdentityRequirement is the configuration for a identity requirement.
type IdentityRequirement struct {
	// Type indicates the requirement for the identity for a successful installation
	// and/or update of a Cluster (within the MinVersionInclusive and MaxVersionInclusive constraints).
	Type IdentityRequirementType
}

// IdentityRequirementType indicates the requirement for the identity for a successful installation
// and/or update of a Cluster (within the MinVersionInclusive and MaxVersionInclusive constraints).
type IdentityRequirementType string

const (
	// IdentityRequirementTypeAlways indicates that the identity is always required.
	IdentityRequirementTypeAlways IdentityRequirementType = "Always"
	// IdentityRequirementTypeOnEnablement indicates that the identity is required only when a functionality that leverages the identity is enabled.
	IdentityRequirementTypeOnEnablement IdentityRequirementType = "OnEnablement"
)

// ClusterScopedIdentityRoleDefinition is the configuration of a cluster scoped identity role definition.
type ClusterScopedIdentityRoleDefinition struct {
	// DescriptiveName is the friendly/descriptive name of the Azure Role Definition.
	DescriptiveName string
	// ResourceID is the resource ID of the Azure Role Definition.
	ResourceID *azcorearm.ResourceID
}

// roleDefinitionConfigSets is the configuration for the role definition config sets.
// There must be an attribute for each RoleDefinitionConfigSetName defined value.
type roleDefinitionConfigSets struct {
	// DevRoleDefinitionConfigSet is the configuration for the DevRoleDefinitionConfigSet role definition config set.
	DevRoleDefinitionConfigSet *RoleDefinitionConfigSet
	// PublicRoleDefinitionConfigSet is the configuration for the PublicRoleDefinitionConfigSet role definition config set.
	PublicRoleDefinitionConfigSet *RoleDefinitionConfigSet
}

// getControlPlaneOperatorsIdentitiesRoleDefinitions returns the control plane operators identities role definitions for the given role set name.
// TODO should we error if role set name is not found, or do we assume that we are going to receive an existing roleSetName?
func (s *roleDefinitionConfigSets) getControlPlaneOperatorsIdentitiesRoleDefinitions(roleSetName RoleDefinitionConfigSetName) ControlPlaneOperatorsIdentitiesRoleDefinitions {
	switch roleSetName {
	case RoleDefinitionConfigSetNameDev:
		return s.DevRoleDefinitionConfigSet.ControlPlaneOperatorsIdentitiesRoleDefinitions
	case RoleDefinitionConfigSetNamePublic:
		return s.PublicRoleDefinitionConfigSet.ControlPlaneOperatorsIdentitiesRoleDefinitions
	}

	return nil
}

// getDataPlaneOperatorsIdentitiesRoleDefinitions returns the data plane operators identities role definitions for the given role set name.
func (s *roleDefinitionConfigSets) getDataPlaneOperatorsIdentitiesRoleDefinitions(roleSetName RoleDefinitionConfigSetName) DataPlaneOperatorsIdentitiesRoleDefinitions {
	switch roleSetName {
	case RoleDefinitionConfigSetNameDev:
		return s.DevRoleDefinitionConfigSet.DataPlaneOperatorsIdentitiesRoleDefinitions
	case RoleDefinitionConfigSetNamePublic:
		return s.PublicRoleDefinitionConfigSet.DataPlaneOperatorsIdentitiesRoleDefinitions
	}
	return nil
}

// getServiceManagedIdentityRoleDefinitions returns the service managed identity role definitions for the given role set name.
func (s *roleDefinitionConfigSets) getServiceManagedIdentityRoleDefinitions(roleSetName RoleDefinitionConfigSetName) ServiceManagedIdentityRoleDefinitions {
	switch roleSetName {
	case RoleDefinitionConfigSetNameDev:
		return s.DevRoleDefinitionConfigSet.ServiceManagedIdentityRoleDefinitions
	case RoleDefinitionConfigSetNamePublic:
		return s.PublicRoleDefinitionConfigSet.ServiceManagedIdentityRoleDefinitions
	}
	return nil
}

// ControlPlaneOperatorsIdentitiesRoleDefinitions is a set of control plane operators along with their identity role definitions.
type ControlPlaneOperatorsIdentitiesRoleDefinitions map[ClusterOperatorIdentifier][]*ClusterScopedIdentityRoleDefinition

// DataPlaneOperatorsIdentitiesRoleDefinitions is a set of data plane operators along with their identity role definitions.
type DataPlaneOperatorsIdentitiesRoleDefinitions map[ClusterOperatorIdentifier][]*ClusterScopedIdentityRoleDefinition

// ServiceManagedIdentityRoleDefinitions are the role definitions for a service managed identity.
type ServiceManagedIdentityRoleDefinitions []*ClusterScopedIdentityRoleDefinition

// RoleDefinitionConfigSet is the configuration for a role definition config set.
type RoleDefinitionConfigSet struct {
	// ControlPlaneOperatorsIdentitiesRoleDefinitions is the set of control plane operators along with their identity role definitions.
	ControlPlaneOperatorsIdentitiesRoleDefinitions ControlPlaneOperatorsIdentitiesRoleDefinitions
	// DataPlaneOperatorsIdentitiesRoleDefinitions is the set of data plane operators along with their identity role definitions.
	DataPlaneOperatorsIdentitiesRoleDefinitions DataPlaneOperatorsIdentitiesRoleDefinitions
	// ServiceManagedIdentityRoleDefinitions is the set of service managed identity role definitions.
	ServiceManagedIdentityRoleDefinitions ServiceManagedIdentityRoleDefinitions
}

// KubernetesServiceAccount is the configuration for a Kubernetes Service Account.
type KubernetesServiceAccount struct {
	// Name is the name of the Kubernetes Service Account.
	Name string
	// Namespace is the namespace of the Kubernetes Service Account.
	Namespace string
}

// AsOidcSubject returns the Kubernetes Service Account as an OIDC subject.
// The format is "system:serviceaccount:<namespace>:<name>".
func (s *KubernetesServiceAccount) AsOIDCSubject() string {
	return fmt.Sprintf("system:serviceaccount:%s:%s", s.Namespace, s.Name)
}
