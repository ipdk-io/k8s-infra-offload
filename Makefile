IMAGE_REGISTRY?=localhost:5000/
IMAGE_VERSION?=latest
KUBECONFIG?=$(HOME)/.kube/config
KUBENAMESPACE?=kube-system
K8S_SECRET_MGR_SERVER?=manager-server-secret
K8S_SECRET_MGR_CLIENT?=manager-client-secret
K8S_SECRET_AGENT_CLIENT?=agent-client-secret
K8S_SECRET_SRC_DIR?=./scripts/tls/certs
TARGET_K8S_VER?=1.28

# KUBECONFIG_CM: ConfigMap with kubeconfig used by Infra Agent.
# If you change the ConfigMap name here dont forget to update the configMap
# volume reference in deploy/infraagent-daemonset.yaml
KUBECONFIG_CM=infra-kubeconfig
export INFRAAGENT_IMAGE?=$(IMAGE_REGISTRY)infraagent:$(IMAGE_VERSION)
export INFRAMANAGER_IMAGE?=$(IMAGE_REGISTRY)inframanager:$(IMAGE_VERSION)

tagname := es2k
arch := amd64

DOCKERARGS?=
ifdef HTTP_PROXY
        DOCKERARGS += --build-arg http_proxy=$(HTTP_PROXY)
endif
ifdef HTTPS_PROXY
        DOCKERARGS += --build-arg https_proxy=$(HTTPS_PROXY)
endif

logdir=/var/log
cnidir=/var/lib/cni
sysconfdir=/etc/infra
datadir=/share/infra/k8s_dp
bindir=/opt/infra
sbindir=/sbin/infra
certdir=/etc/pki
jsonfiles=/share/infra/jsonfiles
host_k8s_ver=$(shell kubelet --version | awk '{print $$2}' | awk -F 'v' '{print $$2}')

RUNFILES:=$(logdir)/arp-proxy* $(logdir)/infra* $(cnidir)/infra* $(sysconfdir)/config.yaml $(datadir)
RUNFILES+=$(bindir)/felix-api* $(bindir)/infra* $(bindir)/arp-proxy*

.PHONY: all

all: check-fmt build

fmt: ## Run go fmt against code.
	go fmt ./...

vet: ## Run go vet against code.
	go vet -tags $(tagname) ./...

check-fmt: ## Check go formatting issues against code.
	./hack/cicd/check-go-fmt.sh

LINTER = $(go env GOPATH)/bin/golangci-lint
lint: golangci-lint
	$(LINTER) run

# Temporary target until SDK is upgraded to use the default or correct target
.PHONY: mev
mev: es2k

es2k:
	@echo "Building project for es2k"
	$(MAKE) tagname=es2k build

dpdk:
	@echo "Building project for dpdk"
	$(MAKE) tagname=dpdk build

build:
	@echo "Building project for $(tagname)"
ifeq ($(tagname),es2k)
	cp -f k8s_dp/es2k/*  k8s_dp/.
	cp -f scripts/es2k/* scripts/.
	cp -f hack/cicd/es2k/run-tests.sh hack/cicd/.
else
	cp -f k8s_dp/dpdk/* k8s_dp/.
	cp -f scripts/dpdk/* scripts/.
	cp -f hack/cicd/dpdk/run-tests.sh hack/cicd/.
endif
	go build -o ./bin/generate-config ./genconf/generate_config.go
	go build -o ./bin/infraagent ./infraagent/agent/main.go
	go build -o ./bin/felix-api-proxy ./infraagent/felix_api_proxy/main.go
	go build -tags $(tagname) -o ./bin/inframanager ./inframanager/cmd/main.go 
	go build -o ./bin/arp-proxy ./arp-proxy/cmd/main.go

BUILDFILES=k8s_dp/*.* scripts/*.sh deploy/infraagent-config.yaml hack/cicd/run-tests.sh

# Make install is used by es2k targets
install: config
	@echo "Installing build artifacts"
	install -d $(DESTDIR)$(cnidir)/inframanager
	install -d $(DESTDIR)$(logdir)/inframanager
	install -d $(DESTDIR)$(sysconfdir)
	install -d $(DESTDIR)$(datadir)
	install -d $(DESTDIR)$(bindir)
	install -d $(DESTDIR)$(sbindir)
	install -d $(DESTDIR)$(jsonfiles)
	install -m 0755 bin/* $(DESTDIR)$(bindir)
	install -C -m 0755 ./deploy/inframanager-config.yaml $(DESTDIR)$(sysconfdir)/inframanager-config.yaml
	install -C -m 0755 ./deploy/infraagent-config.yaml $(DESTDIR)$(sysconfdir)/infraagent-config.yaml
	install -C -m 0755 ./scripts/$(tagname)/*.sh $(DESTDIR)$(sbindir)
	install -C -m 0755 -t $(DESTDIR)$(datadir) ./k8s_dp/$(tagname)/* ./LICENSE
	install -C -m 0755 ./pkg/inframanager/p4/*.json $(DESTDIR)$(jsonfiles)

config:
	./bin/generate-config

test:
	./hack/cicd/run-tests.sh

clean:
	@echo "Remove bin directory"
	rm -rf ./bin $(BUILDFILES)
	rm -rf deploy/inframanager-config.yaml deploy/infraagent-config.yaml

distclean: clean
	pkill arp_proxy || true
	rm -rf ${RUNFILES}

# docker-build now will be with args for tagname and arch
ifeq (docker-build, $(firstword $(MAKECMDGOALS)))
  runargs := $(wordlist 2, $(words $(MAKECMDGOALS)), $(MAKECMDGOALS))
  $(eval $(runargs):;@true)
endif

docker-build: docker-build-manager docker-build-agent

docker-build-agent:
	@echo "Building Docker image $(INFRAAGENT_IMAGE)"
	docker build -f images/Dockerfile.agent -t $(INFRAAGENT_IMAGE) $(DOCKERARGS) .

# docker-build now will be with args for tagname and arch
docker-build-manager:
	@echo "Building Docker image $(INFRAMANAGER_IMAGE) - target $(tagname) arch - $(arch)"
	docker build -f images/Dockerfile.manager -t $(INFRAMANAGER_IMAGE) $(DOCKERARGS) --build-arg TAG=$(tagname) --build-arg ARCH=$(arch) .

docker-build-manager-arm:
	@echo "Building Docker image $(INFRAMANAGER_IMAGE) - target - es2k arch - arm64"
	docker build -f images/Dockerfile.manager-arm64 -t $(INFRAMANAGER_IMAGE) $(DOCKERARGS) .

docker-push: docker-push-agent docker-push-manager

docker-push-agent:
	docker push $(INFRAAGENT_IMAGE)

docker-push-manager:
	docker push $(INFRAMANAGER_IMAGE)

deploy: kustomize create-kubeconfig-cm
	cd deploy  && cp kustomization.yaml.host  kustomization.yaml && $(KUSTOMIZE) edit set image infraagent:latest=$(INFRAAGENT_IMAGE) && $(KUSTOMIZE) edit set image inframanager:latest=$(INFRAMANAGER_IMAGE)
	$(KUSTOMIZE) build --load-restrictor LoadRestrictionsNone deploy | envsubst | kubectl apply -f -

deploy-split: kustomize create-kubeconfig-cm
	cd deploy && cp kustomization.yaml.split  kustomization.yaml && $(KUSTOMIZE) edit set image infraagent:latest=$(INFRAAGENT_IMAGE)
	$(KUSTOMIZE) build --load-restrictor LoadRestrictionsNone deploy | envsubst | kubectl apply -f -

undeploy: kustomize delete-kubeconfig-cm
	cd deploy
	$(KUSTOMIZE) build --load-restrictor LoadRestrictionsNone deploy | envsubst | kubectl delete -f -
	pkill arp_proxy || true
	rm -rf ${RUNFILES}

deploy-calico:
	@if [ $(host_k8s_ver) = $(TARGET_K8S_VER) ]; then \
		kubectl apply -f deploy/calico-with-grpc-3.26.1.yaml ;\
	elif [ "$(TARGET_K8S_VER)" = "`echo -e "$(host_k8s_ver)\n$(TARGET_K8S_VER)" | sort -V | head -n1`" ] ; then \
		kubectl apply -f deploy/calico-with-grpc-3.26.1.yaml ;\
	else \
		kubectl apply -f deploy/calico-with-grpc.yaml ;\
	fi
	kubectl apply -f deploy/felix-configuration.yaml

undeploy-calico:
	kubectl delete -f deploy/felix-configuration.yaml
	@if [ $(host_k8s_ver) = $(TARGET_K8S_VER) ]; then \
		kubectl delete -f deploy/calico-with-grpc-3.26.1.yaml ;\
	elif [ "$(TARGET_K8S_VER)" = "`echo -e "$(host_k8s_ver)\n$(TARGET_K8S_VER)" | sort -V | head -n1`" ] ; then \
		kubectl delete -f deploy/calico-with-grpc-3.26.1.yaml ;\
	else \
		echo "host version is less than target version."; \
		kubectl delete -f deploy/calico-with-grpc.yaml ;\
	fi

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
