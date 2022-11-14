IMAGE_REGISTRY?=localhost:5000/
IMAGE_VERSION?=latest
export INFRAAGENT_IMAGE?=$(IMAGE_REGISTRY)infraagent:$(IMAGE_VERSION)
export INFRAMANAGER_IMAGE?=$(IMAGE_REGISTRY)inframanager:$(IMAGE_VERSION)

#ifdef TARGET
#        tagname=$(TARGET)
#else
#	tagname=mev
#endif

#ifneq ($(tagname), dpdk)
#	ifneq ($(tagname), mev)
#		tagname=mev
#	endif
#endif

tagname:=dpdk

DOCKERARGS?=
ifdef HTTP_PROXY
        DOCKERARGS += --build-arg http_proxy=$(HTTP_PROXY)
endif
ifdef HTTPS_PROXY
        DOCKERARGS += --build-arg https_proxy=$(HTTPS_PROXY)
endif

.PHONY: all

all: check-fmt vet build

fmt: ## Run go fmt against code.
	go fmt ./...

vet: ## Run go vet against code.
	go vet -tags dpdk ./...

check-fmt: ## Check go formatting issues against code.
	./hack/cicd/check-go-fmt.sh

LINTER = $(go env GOPATH)/bin/golangci-lint
lint: golangci-lint
	$(LINTER) run

mev:
	$(MAKE) tagname=mev

build:
	@echo "Building project for $(tagname)"
	go build -o ./bin/infraagent ./infraagent/agent/main.go
	go build -o ./bin/felix-api-proxy ./infraagent/felix_api_proxy/main.go
	go build -tags $(tagname) -o ./bin/inframanager ./inframanager/cmd/main.go 
	go build -o ./bin/arp_proxy ./arp-proxy/cmd/main.go

clean:
	@echo "Remove bin directory"
	rm -rf ./bin

test:
	go test $(shell go list ./... | grep -v manager | grep -v proto | grep -v types) -coverprofile=./cover.out

docker-build: docker-build-agent docker-build-manager

docker-build-agent:
	@echo "Building Docker image $(INFRAAGENT_IMAGE)"
	docker build -f images/Dockerfile.agent -t $(INFRAAGENT_IMAGE) $(DOCKERARGS) .

docker-build-manager:
	@echo "Building Docker image $(INFRAMANAGER_IMAGE)"
	docker build -f images/Dockerfile.manager -t $(INFRAMANAGER_IMAGE) $(DOCKERARGS) --build-arg tagname=$(tagname) .

docker-push: docker-push-agent docker-push-manager

docker-push-agent:
	docker push $(INFRAAGENT_IMAGE)

docker-push-manager:
	docker push $(INFRAMANAGER_IMAGE)

deploy: kustomize
	cd deploy && $(KUSTOMIZE) edit set image infraagent:latest=$(INFRAAGENT_IMAGE) && $(KUSTOMIZE) edit set image inframanager:latest=$(INFRAMANAGER_IMAGE)
	$(KUSTOMIZE) build --load-restrictor LoadRestrictionsNone deploy | envsubst | kubectl apply -f -

undeploy: kustomize
	cd deploy
	$(KUSTOMIZE) build --load-restrictor LoadRestrictionsNone deploy | envsubst | kubectl delete -f -

deploy-calico:
	kubectl apply -f deploy/calico-with-grpc.yaml 
	kubectl apply -f deploy/felix-configuration.yaml

undeploy-calico: 
	kubectl delete -f deploy/felix-configuration.yaml
	kubectl delete -f deploy/calico-with-grpc.yaml

PROJECT_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
define go-get-tool
@[ -f $(1) ] || { \
set -e ;\
TMP_DIR=$$(mktemp -d) ;\
cd $$TMP_DIR ;\
go mod init tmp ;\
echo "Downloading $(2)" ;\
GOBIN=$(PROJECT_DIR)/bin go install $(2) ;\
rm -rf $$TMP_DIR ;\
}
endef

KUSTOMIZE = $(shell pwd)/bin/kustomize
kustomize:
	$(call go-get-tool,$(KUSTOMIZE),sigs.k8s.io/kustomize/kustomize/v4@v4.5.5)

# golangci-lint is not recommended to install via 'go get..' or 'go install..'. Ref:  https://golangci-lint.run/usage/install/
golangci-lint: ## Download golangci-lint locally if necessary.
ifeq (,$(wildcard $(LINTER)))
ifeq (,$(shell which golangci-lint 2>/dev/null))
	@{ \
	set -e ;\
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin; \
	}
else
LINTER = $(shell which golangci-lint)
endif
endif
