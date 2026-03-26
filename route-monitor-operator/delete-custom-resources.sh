#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

# Usage: [DRY_RUN=true] ./delete-custom-resources.sh
#
# Deletes all Route Monitor Operator custom resource instances and CRDs
# This must be run after the Helm release is uninstalled (operator + ACM policy removed)

DRY_RUN="${DRY_RUN:-false}"

echo "Starting cleanup of RMO custom resources"
if [[ "$DRY_RUN" == "true" ]]; then
    echo "DRY RUN MODE - No resources will actually be deleted"
fi

# Function to log actions
log() {
    local level="$1"
    shift
    local message="$*"
    case "$level" in
        INFO) echo "(i) $message" ;;
        WARN) echo "(w) $message" ;;
        ERROR) echo "(!) $message" ;;
        SUCCESS) echo "(o) $message" ;;
        STEP) echo "(~) $message" ;;
    esac
}

# Function to safely delete resources
safe_delete() {
    local resource_type="$1"
    local namespace="${2:-}"
    local description="$3"

    log STEP "Deleting $description..."

    # Get resources as JSON to capture both name and namespace
    local json
    if [[ -n "$namespace" ]]; then
        json=$(kubectl get "$resource_type" -n "$namespace" -o json 2>/dev/null) || {
            log INFO "No $description found (CRD may not exist)"
            return 0
        }
    else
        json=$(kubectl get "$resource_type" --all-namespaces -o json 2>/dev/null) || {
            log INFO "No $description found (CRD may not exist)"
            return 0
        }
    fi

    local count
    count=$(echo "$json" | jq '.items | length')
    if [[ "$count" -eq 0 ]]; then
        log INFO "No $description found"
        return 0
    fi

    echo "$json" | jq -r '.items[] | "\(.metadata.namespace) \(.metadata.name)"' | \
        while read -r ns name; do
            if [[ "$DRY_RUN" == "true" ]]; then
                log INFO "[DRY RUN] Would delete: $name in namespace: $ns"
            else
                log INFO "Deleting: $name in namespace: $ns"
                # Remove finalizers so deletion doesn't hang after operator is gone
                kubectl patch "$resource_type" "$name" -n "$ns" \
                    -p '{"metadata":{"finalizers":[]}}' --type=merge 2>/dev/null || true
                if kubectl delete "$resource_type" "$name" -n "$ns" --ignore-not-found=true --timeout=60s 2>/dev/null; then
                    log SUCCESS "Deleted: $name in namespace: $ns"
                else
                    log WARN "Failed to delete: $name in namespace: $ns (may already be gone)"
                fi
            fi
        done
}

# Step 1: Delete ClusterUrlMonitor instances
log STEP "Step 1: Deleting ClusterUrlMonitor instances"
safe_delete "clusterurlmonitors.monitoring.openshift.io" "" "ClusterUrlMonitor instances"

# Step 2: Delete RouteMonitor instances
log STEP "Step 2: Deleting RouteMonitor instances"
safe_delete "routemonitors.monitoring.openshift.io" "" "RouteMonitor instances"

# Step 3: Delete ServiceMonitor instances (monitoring.rhobs)
log STEP "Step 3: Deleting ServiceMonitor (monitoring.rhobs) instances"
safe_delete "servicemonitors.monitoring.rhobs" "" "ServiceMonitor (monitoring.rhobs) instances"

# Step 4: Wait for resources to be fully deleted
if [[ "$DRY_RUN" != "true" ]]; then
    log INFO "Waiting for resources to be fully deleted..."
    for crd in clusterurlmonitors.monitoring.openshift.io routemonitors.monitoring.openshift.io servicemonitors.monitoring.rhobs; do
        if kubectl get crd "$crd" > /dev/null 2>&1; then
            kubectl wait --for=delete "$crd" --all --all-namespaces --timeout=60s 2>/dev/null && \
                log SUCCESS "All $crd instances deleted" || \
                log WARN "Timed out waiting for $crd instances to be deleted"
        fi
    done
fi

# Step 5: Delete RMO CRDs
log STEP "Step 5: Deleting RMO CRDs"

RMO_CRDS=(
    "clusterurlmonitors.monitoring.openshift.io"
    "routemonitors.monitoring.openshift.io"
    "servicemonitors.monitoring.rhobs"
)

for crd in "${RMO_CRDS[@]}"; do
    if kubectl get crd "$crd" > /dev/null 2>&1; then
        if [[ "$DRY_RUN" == "true" ]]; then
            log INFO "[DRY RUN] Would delete CRD: $crd"
        else
            log INFO "Deleting CRD: $crd"
            kubectl patch crd "$crd" -p '{"metadata":{"finalizers":[]}}' --type=merge 2>/dev/null || true
            if kubectl delete crd "$crd" --ignore-not-found=true --timeout=60s 2>&1; then
                log SUCCESS "CRD deleted: $crd"
            else
                log WARN "Failed to delete CRD: $crd"
            fi
        fi
    else
        log INFO "CRD not found: $crd (already deleted)"
    fi
done

log SUCCESS "RMO custom resources cleanup completed"
