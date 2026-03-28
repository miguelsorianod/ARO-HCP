SHELL = /bin/bash
THIS := $(lastword $(MAKEFILE_LIST))
DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

-include ../setup-templatize-env.mk
-include ../tooling/hcpctl/Variables.mk
include Makefile

LOCAL_PORT ?= 8443
AROHCP_ENV ?= development
CUSTOMER_SUBSCRIPTION ?= $$(az account show --output tsv --query 'name')

e2e-local/run-test: $(ARO_HCP_TESTS)
	$(MAKE) -C $(DIR) -f $(THIS) .e2e-local/setup
	export LOCATION="$${LOCATION:-${REGION}}"; \
	export AROHCP_ENV="development"; \
	export CUSTOMER_SUBSCRIPTION="$$(az account show --output tsv --query 'name')"; \
	export SKIP_CERT_VERIFICATION=$${SKIP_CERT_VERIFICATION:-false}; \
	export FRONTEND_ADDRESS=$${FRONTEND_ADDRESS:-http://localhost:8443}; \
	$(ARO_HCP_TESTS) run-test "$$TEST_NAME"
.PHONY: e2e-local/run-test

e2e-local/pf/run-test: $(HCPCTL)
	HCPCTL=$(HCPCTL) ../hack/run-with-port-forward.sh "${SVC_CLUSTER}" "aro-hcp/aro-hcp-frontend/$(LOCAL_PORT)/8443" \
		$(MAKE) -C $(DIR) -f $(THIS) e2e-local/run-test SKIP_CERT_VERIFICATION=true FRONTEND_ADDRESS=http://localhost:$(LOCAL_PORT)
.PHONY: e2e-local/pf/run-test

.e2e-local/setup:
	SUBSCRIPTION_ID="$$(az account show --query id --output tsv)"; \
	TENANT_ID="$$(az account show --query tenantId --output tsv)"; \
	curl --silent --show-error --include \
		--insecure \
		--request PUT \
		--header "Content-Type: application/json" \
		--data '{"state":"Registered", "registrationDate": "now", "properties": { "tenantId": "'$${TENANT_ID}'", "registeredFeatures": [{"name": "Microsoft.RedHatOpenShift/ExperimentalReleaseFeatures", "state": "Registered"}]}}' \
		"http://localhost:${LOCAL_PORT}/subscriptions/$${SUBSCRIPTION_ID}?api-version=2.0"
.PHONY: .e2e-local/setup
