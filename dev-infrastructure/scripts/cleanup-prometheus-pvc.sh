#!/bin/bash
set -euo pipefail

# Inputs via environment variables:
#   AGENT_MODE - "true" or "false", whether Prometheus is in agent mode

NAMESPACE="prometheus"
PVC_LABEL_SELECTOR="operator.prometheus.io/name=prometheus"

if [ "${AGENT_MODE}" != "true" ]; then
  echo "Agent mode is not enabled, skipping PVC cleanup."
  exit 0
fi

PVCS=$(kubectl get pvc -n "${NAMESPACE}" -l "${PVC_LABEL_SELECTOR}" -o name 2>/dev/null || true)

if [ -z "${PVCS}" ]; then
  echo "No Prometheus PVCs found in namespace '${NAMESPACE}'. Nothing to do."
  exit 0
fi

for PVC in ${PVCS}; do
  echo "Deleting orphaned ${PVC} in namespace '${NAMESPACE}'..."
  kubectl delete "${PVC}" -n "${NAMESPACE}"
done

echo "PVC cleanup complete."
