// Copyright (c) 2022 Intel Corporation.  All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License")
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"

	conf "github.com/ipdk-io/k8s-infra-offload/pkg/inframanager/config"
	"github.com/ipdk-io/k8s-infra-offload/pkg/inframanager/store"

	"github.com/antoninbas/p4runtime-go-client/pkg/client"
	"github.com/antoninbas/p4runtime-go-client/pkg/signals"
	api "github.com/ipdk-io/k8s-infra-offload/inframanager/api_handler"
	mgr "github.com/ipdk-io/k8s-infra-offload/pkg/inframanager"
)

func main() {
	config := &conf.Configuration{}
	conf.ReadConfig(config, "./config.yaml")

	if config.P4BinPath == "" || config.P4InfoPath == "" {
		log.Fatalf("Missing .bin or P4Info")
	}

	api.PutConf(config)

	p4InfoPath, err := filepath.Abs(config.P4InfoPath)
	if err != nil {
		log.Fatalf("Failed to get absolute representation of path %s",
			config.P4InfoPath)
	}
	p4BinPath, err := filepath.Abs(config.P4BinPath)
	if err != nil {
		log.Fatalf("Failed to get absolute representation of path %s",
			config.P4BinPath)
	}

	ctx := context.Background()
	stopCh := signals.RegisterSignalHandlers()

	api.NewApiServer()
	store.NewEndPoint()
	store.NewService()

	if err := api.OpenP4RtC(ctx, 0, 1, stopCh); err != nil {
		log.Errorf("Failed to open p4 runtime client connection")
		os.Exit(1)
	}
	defer api.CloseP4RtCCon()

	if err := api.OpenGNMICCon(); err != nil {
		log.Errorf("Failed to open gNMI client connection")
		os.Exit(1)
	}
	defer api.CloseGNMIConn()

	log.Infof("getting pipeline if already set")
	pipelineConfig, err := api.GetFwdPipe(ctx, client.GetFwdPipeAll)
	if err == nil {
		log.Infof("pipeline is already set")
		if pipelineConfig.P4Info == nil {
			log.Errorf("p4Info is null")
			api.CloseP4RtCCon()
			api.CloseGNMIConn()
			os.Exit(1)
		}
		store.InitEndPointStore(false)
		store.InitServiceStore(false)
	} else {
		// Setting fwding pipeline
		log.Infof("Setting the pipeline")

		if _, err := api.SetFwdPipe(ctx, p4BinPath, p4InfoPath,
			0); err != nil {
			log.Errorf("Error when setting forwarding pipe: %v", err)
			api.CloseP4RtCCon()
			api.CloseGNMIConn()
			os.Exit(1)
		}
		store.InitEndPointStore(true)
		store.InitServiceStore(true)
	}

	// Starting inframanager gRPC server
	waitCh := make(chan struct{})
	mgr.NewManager()
	go mgr.Run(stopCh, waitCh)

	// Wait till manager is exited
	<-waitCh
	log.Infof("Exiting program")
}
