#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

# Usage: [DRY_RUN=true] ./delete-ingresscontroller-hack.sh
#
# Deletes the IngressController hack resources created for RMO
# This includes:
# - IngressController CR "default" in openshift-ingress-operator namespace
# - IngressController CRD
# - openshift-ingress-operator namespace (if empty)

DRY_RUN="${DRY_RUN:-false}"

echo "Starting cleanup of RMO IngressController hack"
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

# Step 1: Delete the "default" IngressController CR
log STEP "Step 1: Deleting IngressController CR 'default'"

if kubectl get ingresscontrollers.operator.openshift.io default -n openshift-ingress-operator > /dev/null 2>&1; then
    if [[ "$DRY_RUN" == "true" ]]; then
        log INFO "[DRY RUN] Would delete IngressController: default"
    else
        log INFO "Deleting IngressController: default"
        # Remove finalizers if present to ensure clean deletion
        kubectl patch ingresscontrollers.operator.openshift.io default -n openshift-ingress-operator \
            -p '{"metadata":{"finalizers":[]}}' --type=merge 2>/dev/null || true

        if kubectl delete ingresscontrollers.operator.openshift.io default -n openshift-ingress-operator --timeout=60s 2>&1; then
            log SUCCESS "Deleted IngressController: default"
        else
            log WARN "Failed to delete IngressController: default (may already be gone)"
        fi
    fi
else
    log INFO "IngressController 'default' not found (already deleted)"
fi

# Step 2: Wait for CR to be fully deleted
if [[ "$DRY_RUN" != "true" ]]; then
    if kubectl get crd ingresscontrollers.operator.openshift.io > /dev/null 2>&1; then
        log INFO "Waiting for IngressController instances to be fully deleted..."
        kubectl wait --for=delete ingresscontrollers.operator.openshift.io --all -n openshift-ingress-operator --timeout=60s 2>/dev/null && \
            log SUCCESS "All IngressController instances deleted" || \
            log WARN "Timed out waiting for IngressController instances to be deleted"
    fi
fi

# Step 3: Delete the IngressController CRD
log STEP "Step 3: Deleting IngressController CRD"

if kubectl get crd ingresscontrollers.operator.openshift.io > /dev/null 2>&1; then
    if [[ "$DRY_RUN" == "true" ]]; then
        log INFO "[DRY RUN] Would delete CRD: ingresscontrollers.operator.openshift.io"
    else
        log INFO "Deleting CRD: ingresscontrollers.operator.openshift.io"
        kubectl patch crd ingresscontrollers.operator.openshift.io \
            -p '{"metadata":{"finalizers":[]}}' --type=merge 2>/dev/null || true
        if kubectl delete crd ingresscontrollers.operator.openshift.io --ignore-not-found=true --timeout=60s 2>&1; then
            log SUCCESS "Deleted CRD: ingresscontrollers.operator.openshift.io"
        else
            log WARN "Failed to delete CRD: ingresscontrollers.operator.openshift.io"
        fi
    fi
else
    log INFO "CRD 'ingresscontrollers.operator.openshift.io' not found (already deleted)"
fi

# Step 4: Delete the openshift-ingress-operator namespace
log STEP "Step 4: Deleting namespace: openshift-ingress-operator"

if kubectl get namespace openshift-ingress-operator > /dev/null 2>&1; then
    if [[ "$DRY_RUN" == "true" ]]; then
        log INFO "[DRY RUN] Would delete namespace: openshift-ingress-operator"
    else
        kubectl delete all --all -n openshift-ingress-operator --timeout=60s 2>&1 || true
        if kubectl delete namespace openshift-ingress-operator --timeout=60s 2>&1; then
            log SUCCESS "Namespace deleted: openshift-ingress-operator"
        else
            log WARN "Failed to delete namespace: openshift-ingress-operator"
        fi
    fi
else
    log INFO "Namespace 'openshift-ingress-operator' not found (already deleted)"
fi

log SUCCESS "IngressController hack cleanup completed"
