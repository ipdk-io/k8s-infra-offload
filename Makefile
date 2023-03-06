IMAGE_REGISTRY?=localhost:5000/
IMAGE_VERSION?=latest
KUBECONFIG?=$(HOME)/.kube/config
KUBENAMESPACE?=kube-system
K8S_SECRET_MGR_SERVER?=manager-server-secret
K8S_SECRET_MGR_CLIENT?=manager-client-secret
K8S_SECRET_AGENT_CLIENT?=agent-client-secret
K8S_SECRET_SRC_DIR?=./scripts/tls/certs

# KUBECONFIG_CM: ConfigMap with kubeconfig used by Infra Agent.
# If you change the ConfigMap name here dont forget to update the configMap
# volume reference in deploy/infraagent-daemonset.yaml
KUBECONFIG_CM=infra-kubeconfig
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

tagname := dpdk

DOCKERARGS?=
ifdef HTTP_PROXY
        DOCKERARGS += --build-arg http_proxy=$(HTTP_PROXY)
endif
ifdef HTTPS_PROXY
        DOCKERARGS += --build-arg https_proxy=$(HTTPS_PROXY)
endif

LOGDIR := /var/log
CNIDIR := /var/lib/cni

RUNDIRS := ${LOGDIR}/arp_proxy* ${CNIDIR}/infra*

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
	go build -v -x -gcflags="all=-N -l" -tags $(tagname) -o ./bin/inframanager ./inframanager/cmd/main.go 
	go build -o ./bin/arp_proxy ./arp-proxy/cmd/main.go

clean:
	@echo "Remove bin directory"
	rm -rf ./bin

clean-dirs:
	pkill arp_proxy || true
	rm -rf ${RUNDIRS}

test:
	./hack/cicd/run-tests.sh

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

deploy: kustomize create-kubeconfig-cm
	cd deploy && $(KUSTOMIZE) edit set image infraagent:latest=$(INFRAAGENT_IMAGE) && $(KUSTOMIZE) edit set image inframanager:latest=$(INFRAMANAGER_IMAGE)
	$(KUSTOMIZE) build --load-restrictor LoadRestrictionsNone deploy | envsubst | kubectl apply -f -

undeploy: clean-dirs kustomize delete-kubeconfig-cm
	cd deploy
	$(KUSTOMIZE) build --load-restrictor LoadRestrictionsNone deploy | envsubst | kubectl delete -f -

deploy-calico:
	kubectl apply -f deploy/calico-with-grpc.yaml 
	kubectl apply -f deploy/felix-configuration.yaml

undeploy-calico: 
	kubectl delete -f deploy/felix-configuration.yaml
	kubectl delete -f deploy/calico-with-grpc.yaml

create-kubeconfig-cm:
	@echo "Using kubeconfig file:$(KUBECONFIG)"
	kubectl -n kube-system create configmap $(KUBECONFIG_CM) --from-file=config=$(KUBECONFIG)
delete-kubeconfig-cm:
	kubectl -n kube-system delete configmap $(KUBECONFIG_CM)

.PHONY : tls-secrets
tls-secrets:
	# Do clean up first if there's any left-over secrets
	kubectl -n $(KUBENAMESPACE) delete secret $(K8S_SECRET_MGR_SERVER) || true
	kubectl -n $(KUBENAMESPACE) delete secret $(K8S_SECRET_MGR_CLIENT) || true
	kubectl -n $(KUBENAMESPACE) delete secret $(K8S_SECRET_AGENT_CLIENT) || true
	# Create new secrets from generated certs
	kubectl -n $(KUBENAMESPACE) create secret generic $(K8S_SECRET_MGR_SERVER) --from-file=$(K8S_SECRET_SRC_DIR)/inframanager/server/
	kubectl -n $(KUBENAMESPACE) create secret generic $(K8S_SECRET_MGR_CLIENT) --from-file=$(K8S_SECRET_SRC_DIR)/inframanager/client/
	kubectl -n $(KUBENAMESPACE) create secret generic $(K8S_SECRET_AGENT_CLIENT) --from-file=$(K8S_SECRET_SRC_DIR)/infraagent/client/

.PHONY : gen-certs
gen-certs:
	 ./scripts/tls/gen_certs.sh

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
