#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail

DRY_RUN="${DRY_RUN:-false}"

if [[ "$DRY_RUN" == "true" ]]; then
    echo "DRY RUN MODE - showing current state"
    helm list -n openshift-route-monitor-operator
    kubectl get crd clusterurlmonitors.monitoring.openshift.io routemonitors.monitoring.openshift.io servicemonitors.monitoring.rhobs ingresscontrollers.operator.openshift.io 2>/dev/null || true
    kubectl get namespace openshift-route-monitor-operator openshift-ingress-operator 2>/dev/null || true
    exit 0
fi

echo "Uninstalling Helm release..."
helm uninstall route-monitor-operator -n openshift-route-monitor-operator --wait --timeout=5m 2>/dev/null || true

echo "Deleting CRDs and all custom resources..."
for crd in clusterurlmonitors.monitoring.openshift.io routemonitors.monitoring.openshift.io servicemonitors.monitoring.rhobs ingresscontrollers.operator.openshift.io; do
    kubectl delete crd "$crd" --force --wait=false --ignore-not-found=true 2>/dev/null || true
    kubectl patch crd "$crd" --type=merge -p '{"metadata":{"finalizers":null}}' 2>/dev/null || true
done

echo "Deleting namespaces..."
kubectl delete namespace openshift-route-monitor-operator openshift-ingress-operator --force --wait=false --ignore-not-found=true 2>/dev/null || true

echo "Route Monitor Operator removal complete"
