#!/bin/bash
set -euo pipefail

# Cleans up orphaned PVCs from the old Prometheus server-mode StatefulSet
# after migrating to PrometheusAgent. The old StatefulSet was named
# "prometheus-prometheus", while the new one is "prom-agent-prometheus".

NAMESPACE="prometheus"
OLD_PVC_PREFIX="prometheus-prometheus-db-prometheus-prometheus-"

PVCS=$(kubectl get pvc -n "${NAMESPACE}" -o name 2>/dev/null | grep "${OLD_PVC_PREFIX}" || true)

if [ -z "${PVCS}" ]; then
  echo "No old Prometheus server PVCs found in namespace '${NAMESPACE}'. Nothing to do."
  exit 0
fi

for PVC in ${PVCS}; do
  echo "Deleting orphaned ${PVC} in namespace '${NAMESPACE}'..."
  kubectl delete "${PVC}" -n "${NAMESPACE}"
done

echo "PVC cleanup complete."
