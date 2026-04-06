YAMLFMT_LINK := $(GOBIN)/yamlfmt
$(YAMLFMT_LINK): $(YAMLFMT)
	@echo "creating symlink for $(YAMLFMT) at $(YAMLFMT_LINK)"
	@rm -f $(YAMLFMT_LINK)
	@ln -s $(YAMLFMT) $(YAMLFMT_LINK)

ORAS_LINK := $(GOBIN)/oras
$(ORAS_LINK): $(ORAS)
	@echo "creating symlink for $(ORAS) at $(ORAS_LINK)"
	@rm -f $(ORAS_LINK)
	@ln -s $(ORAS) $(ORAS_LINK)

HELM_LINK := $(GOBIN)/helm
$(HELM_LINK): $(HELM)
	@echo "creating symlink for $(HELM) at $(HELM_LINK)"
	@rm -f $(HELM_LINK)
	@ln -s $(HELM) $(HELM_LINK)

YQ_LINK := $(GOBIN)/yq
$(YQ_LINK): $(YQ)
	@echo "creating symlink for $(YQ) at $(YQ_LINK)"
	@rm -f $(YQ_LINK)
	@ln -s $(YQ) $(YQ_LINK)
	
JQ := $(GOBIN)/jq
$(JQ): $(GOJQ)
	@echo "creating symlink for $(GOJQ) at $(JQ)"
	@rm -f $(JQ)
	@ln -s $(GOJQ) $(JQ)
