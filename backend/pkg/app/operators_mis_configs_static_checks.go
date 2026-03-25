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

package app

import (
	"fmt"
	"strings"

	"github.com/blang/semver/v4"

	"github.com/Azure/ARO-HCP/internal/api"
	internalazure "github.com/Azure/ARO-HCP/internal/azure"
)

// validateUnknownAndUnsupportedManagedIdentities checks for unknown and unsupported managed identities for the given cluster
// and operators managed identities configuration. It returns an error if any unknown or unsupported managed identities are found.
// An unknown managed identity is a managed identity whose operator name is not defined in the operators managed identities configuration.
// An unsupported managed identity is a managed identity whose operator name is defined in the operators managed identities configuration
// but it is not defined within the minOpenShiftVersion and maxOpenShiftVersion constraints defined in the operators managed identities configuration.
func validateUnknownAndUnsupportedManagedIdentities(cluster *api.HCPOpenShiftCluster, clusterScopedIdentitiesConfig *internalazure.ClusterScopedIdentitiesConfig) error {
	err := validateUnknownAndUnsupportedControlPlaneManagedIdentities(cluster, clusterScopedIdentitiesConfig)
	if err != nil {
		return err
	}

	err = validateUnknownAndUnsupportedDataPlaneManagedIdentities(cluster, clusterScopedIdentitiesConfig)
	if err != nil {
		return err
	}

	return nil
}

// validateUnknownAndUnsupportedControlPlaneManagedIdentities checks for uknown and unsupported managed identities for the
// given cluster and operators managed identities configuration. It returns an error if any unknown or unsupported control plane managed identities are found.
func validateUnknownAndUnsupportedControlPlaneManagedIdentities(cluster *api.HCPOpenShiftCluster, clusterScopedIdentitiesConfig *internalazure.ClusterScopedIdentitiesConfig) error {
	unknownIdentitiesFound := []string{}
	unsupportedIdentitiesFound := []string{}
	extraIdentities := []string{}
	// TODO will we need to execute this validations on cluster and/or nodepool upgrades? if so, how would we retrieve the OpenShift version?
	ocpVersion := api.Ptr(api.Must(semver.ParseTolerant(cluster.CustomerProperties.Version.ID)))

	controlPlaneOperatorsManagedIdentities := cluster.CustomerProperties.Platform.OperatorsAuthentication.UserAssignedIdentities.ControlPlaneOperators

	for operatorName := range controlPlaneOperatorsManagedIdentities {
		identity, isKnown := clusterScopedIdentitiesConfig.ControlPlaneOperatorsIdentities[internalazure.ClusterOperatorIdentifier(operatorName)]
		if !isKnown {
			unknownIdentitiesFound = append(unknownIdentitiesFound, operatorName)
			continue
		}

		isSupported := identity.IsSupportedForOpenshiftVersion(ocpVersion)
		if !isSupported {
			unsupportedIdentitiesFound = append(unsupportedIdentitiesFound, operatorName)
			continue
		}

		// Check if the identity is required only on feature enablement
		if identity.Requirement.Type == internalazure.IdentityRequirementTypeAlways {
			isFeatureEnabled := isOperatorFeatureEnabled(operatorName, cluster)
			if !isFeatureEnabled {
				extraIdentities = append(extraIdentities, operatorName)
			}
		}
	}

	var errMsg []string
	if len(unknownIdentitiesFound) > 0 {
		errMsg = append(errMsg, fmt.Sprintf("unknown managed identities: [%s]", strings.Join(unknownIdentitiesFound, ", ")))
	}
	if len(unsupportedIdentitiesFound) > 0 {
		errMsg = append(errMsg, fmt.Sprintf("unsupported managed identities for %s openshift version: [%s]",
			ocpVersion, strings.Join(unsupportedIdentitiesFound, ", ")))
	}
	if len(extraIdentities) > 0 {
		errMsg = append(errMsg, fmt.Sprintf("extra managed identities without corresponding feature enablement "+
			"for %s openshift version: [%s]",
			ocpVersion, strings.Join(extraIdentities, ", ")))
	}

	if len(errMsg) > 0 {
		return fmt.Errorf("invalid control plane managed identities detected. Please remove these identities: %s", strings.Join(errMsg, " | "))
	}

	return nil
}

// validateUnknownAndUnsupportedDataPlaneManagedIdentities checks for uknown and unsupported managed identities for the
// given cluster and operators managed identities configuration. It returns an error if any unknown or unsupported data plane managed identities are found.
func validateUnknownAndUnsupportedDataPlaneManagedIdentities(cluster *api.HCPOpenShiftCluster, clusterScopedIdentitiesConfig *internalazure.ClusterScopedIdentitiesConfig) error {
	unknownIdentitiesFound := []string{}
	unsupportedIdentitiesFound := []string{}
	extraIdentities := []string{}
	// TODO will we need to execute this validations on cluster and/or nodepool upgrades? if so, how would we retrieve the OpenShift version?
	ocpVersion := api.Ptr(api.Must(semver.ParseTolerant(cluster.CustomerProperties.Version.ID)))
	dataPlaneOperatorsManagedIdentities := cluster.CustomerProperties.Platform.OperatorsAuthentication.UserAssignedIdentities.DataPlaneOperators

	for operatorName := range dataPlaneOperatorsManagedIdentities {
		identity, isKnown := clusterScopedIdentitiesConfig.DataPlaneOperatorsIdentities[internalazure.ClusterOperatorIdentifier(operatorName)]
		if !isKnown {
			unknownIdentitiesFound = append(unknownIdentitiesFound, operatorName)
			continue
		}

		isSupported := identity.IsSupportedForOpenshiftVersion(ocpVersion)
		if !isSupported {
			unsupportedIdentitiesFound = append(unsupportedIdentitiesFound, operatorName)
			continue
		}

		// Check if the identity is required only on feature enablement
		if identity.Requirement.Type == internalazure.IdentityRequirementTypeOnEnablement {
			isFeatureEnabled := isOperatorFeatureEnabled(operatorName, cluster)
			if !isFeatureEnabled {
				extraIdentities = append(extraIdentities, operatorName)
			}
		}
	}

	var errMsg []string

	if len(unknownIdentitiesFound) > 0 {
		errMsg = append(errMsg, fmt.Sprintf("unknown managed identities: [%s]", strings.Join(unknownIdentitiesFound, ", ")))
	}
	if len(unsupportedIdentitiesFound) > 0 {
		errMsg = append(errMsg, fmt.Sprintf("unsupported managed identities for %s openshift version: [%s]",
			ocpVersion, strings.Join(unsupportedIdentitiesFound, ", ")))
	}
	if len(extraIdentities) > 0 {
		errMsg = append(errMsg, fmt.Sprintf("extra managed identities without corresponding feature enablement "+
			"for %s openshift version: [%s]",
			ocpVersion, strings.Join(extraIdentities, ", ")))
	}

	if len(errMsg) > 0 {
		return fmt.Errorf("invalid data plane managed identities detected. Please remove these identities: %s", strings.Join(errMsg, " | "))
	}

	return nil
}

// isOperatorFeatureEnabled checks if the feature corresponding to the given operator is enabled for the given
// cluster. It returns true if the feature is enabled, false otherwise.
func isOperatorFeatureEnabled(operatorName string, cluster *api.HCPOpenShiftCluster) bool {
	switch operatorName {
	case string(internalazure.ClusterOperatorIdentifierKMS):
		return cluster.CustomerProperties.Etcd.DataEncryption.CustomerManaged.EncryptionType == api.CustomerManagedEncryptionTypeKMS
	// Add more cases here as new conditional features are implemented
	// Important: When adding new cases make sure that you update the
	// validateRequiredWhenEnabledControlPlaneIdentities and/or the
	// validateRequiredWhenEnabledDataPlaneIdentities function to contain
	// the other side of the comparison.
	// case models.ParseAzureOperatorName("some-other-operator"):
	//     return cluster.SomeFeature.Enabled
	default:
		// For unknown operators with RequiredOnEnablementIdentityRequirement,
		// assume the feature is disabled (identity not needed)
		return false
	}
}
