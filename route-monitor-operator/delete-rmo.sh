#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail

DRY_RUN="${DRY_RUN:-true}"

if [[ "$DRY_RUN" == "true" ]]; then
    echo "DRY RUN MODE - showing current state"
    helm list -n openshift-route-monitor-operator
    kubectl get crd clusterurlmonitors.monitoring.openshift.io routemonitors.monitoring.openshift.io servicemonitors.monitoring.rhobs ingresscontrollers.operator.openshift.io 2>/dev/null || true
    kubectl get namespace openshift-route-monitor-operator openshift-ingress-operator 2>/dev/null || true
    exit 0
fi

# Helm uninstall handles cluster-scoped resources (ClusterRoles, ClusterRoleBindings)
helm uninstall route-monitor-operator -n openshift-route-monitor-operator --wait --timeout=5m 2>/dev/null || true

# Delete all custom resources across all namespaces
kubectl delete clusterurlmonitors.monitoring.openshift.io --all --all-namespaces --force --ignore-not-found=true 2>/dev/null || true
kubectl delete routemonitors.monitoring.openshift.io --all --all-namespaces --force --ignore-not-found=true 2>/dev/null || true
kubectl delete servicemonitors.monitoring.rhobs --all --all-namespaces --force --ignore-not-found=true 2>/dev/null || true
kubectl delete ingresscontrollers.operator.openshift.io --all --all-namespaces --force --ignore-not-found=true 2>/dev/null || true

# Delete CRDs
kubectl delete crd clusterurlmonitors.monitoring.openshift.io routemonitors.monitoring.openshift.io servicemonitors.monitoring.rhobs ingresscontrollers.operator.openshift.io --force --ignore-not-found=true

# Delete namespaces
kubectl delete namespace openshift-route-monitor-operator openshift-ingress-operator --force --ignore-not-found=true
