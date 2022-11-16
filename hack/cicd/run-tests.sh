#!/bin/bash
#Copyright (C) 2022 Intel Corporation
#SPDX-License-Identifier: Apache-2.0

LOCALBIN=$(pwd)/hack/cicd/bin/
mkdir -p $LOCALBIN
SETUP_ENVTEST=$LOCALBIN/setup-envtest

if [ ! -f "$SETUP_ENVTEST" ]; then
    GOBIN=$LOCALBIN go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest
fi
export KUBEBUILDER_ASSETS=$($SETUP_ENVTEST use | grep -oP '[^\s]*kubebuilder[^\s]*')

go test $(go list ./... | grep -v manager | grep -v proto | grep -v types) -coverprofile=./cover.out
