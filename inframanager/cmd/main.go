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

	conf "github.com/ipdk-io/k8s-infra-offload/inframanager/config"

	"github.com/antoninbas/p4runtime-go-client/pkg/client"
	"github.com/antoninbas/p4runtime-go-client/pkg/signals"
	api "github.com/ipdk-io/k8s-infra-offload/inframanager/api-handler"
	mgr "github.com/ipdk-io/k8s-infra-offload/pkg/inframanager"
)

func main() {
	config := &conf.Configuration{}
	conf.ReadConfig(config, "./config.yaml")

	if config.P4BinPath == "" || config.P4InfoPath == "" {
		log.Fatalf("Missing .bin or P4Info")
	}

	api.PutConf(config)

	p4InfoPath, _ := filepath.Abs(config.P4InfoPath)
	p4BinPath, _ := filepath.Abs(config.P4BinPath)

	ctx := context.Background()
	stopCh := signals.RegisterSignalHandlers()

	api.NewApiServer()

	if err := api.OpenP4RtC(ctx, 0, 1, stopCh); err != nil {
		log.Infof("Failed to open p4 runtime client connection")
		api.CloseCon()
		os.Exit(1)
	}
	defer api.CloseCon()

	log.Infof("getting pipeline if already set")
	pipelineConfig, err := api.GetFwdPipe(ctx, client.GetFwdPipeAll)
	if err == nil {
		log.Infof("pipeline is already set")
		if pipelineConfig.P4Info == nil {
			log.Fatalf("p4info is null")
		}
	} else {
		// Setting fwding pipeline
		log.Infof("Setting the pipeline")

		if _, err := api.SetFwdPipe(ctx, p4BinPath, p4InfoPath, 0); err != nil {
			log.Fatalf("Error when setting forwarding pipe: %v", err)
		}
	}

	// Starting inframanager gRPC server
	mgr.NewManager()
	go mgr.Run()

	<-stopCh
}
