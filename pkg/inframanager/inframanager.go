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

package inframanager

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/antoninbas/p4runtime-go-client/pkg/client"
	api "github.com/ipdk-io/k8s-infra-offload/inframanager/api_handler"
	"github.com/ipdk-io/k8s-infra-offload/pkg/inframanager/config"
	"github.com/ipdk-io/k8s-infra-offload/pkg/inframanager/store"
	"github.com/ipdk-io/k8s-infra-offload/pkg/types"
	"github.com/ipdk-io/k8s-infra-offload/pkg/utils"
	"github.com/spf13/viper"
	"gopkg.in/tomb.v2"

	log "github.com/sirupsen/logrus"
)

const (
	logDir = "/var/log/inframanager"
)

type Manager struct {
	server *api.ApiServer
	conf   *config.Configuration
	log    *log.Entry
	t      tomb.Tomb
}

var manager *Manager

func NewManager(conf *config.Configuration) {
	err := utils.LogInit(logDir, conf.LogLevel)
	if err != nil {
		return
	}
	utils.CreateCipherMap()

	manager = &Manager{
		log:  log.WithField("pkg", "inframanager"),
		conf: conf,
	}
	/*
		Set infrap4d to running state by default
	*/
	api.Infrap4d.SetRunning()

	mgrAddr := viper.GetString("InfraManager.Addr")
	values := strings.Split(mgrAddr, ":")
	types.InfraManagerAddr = values[0]
	types.InfraManagerPort = values[1]
}

func (m *Manager) createAndStartServer() {
	m.server = api.CreateServer(m.conf, m.log)
	m.server.Start(&m.t)
}

func (m *Manager) stopServer() {
	m.t.Kill(fmt.Errorf("%s", "Stopping server"))
	if err := m.t.Wait(); err != nil {
		log.Errorf("stop server error %s", err)
	}
}

func (m *Manager) Infrap4dStatusCheck() {
	logger := m.log.WithField("func", "Infrap4dStatusCheck")
	for {
		select {
		case <-m.conf.StopCh:
			logger.Infof("Manager is exiting. Stopping infrap4d status check")
			return
		default:
			//Checking infrap4d server status
			if !infrap4dRunning() {
				logger.Errorf("Cannot connect to infrap4d, reconnecting..")
				// Let api server know that the infrap4d is not running
				api.Infrap4d.SetStopped()
				//Try reconnecting to infrap4d
				for {
					logger.Infof("Try reconnecting to infrap4d")
					if m.reconnectInfrap4d() {
						logger.Infof("Successfully reconnected")
						api.SetReplay()

						logger.Infof("Reprogramming all rules")
						//Reprogram all rules
						api.ReplayRules()

						api.ClearReplay()

						// Set infrap4d to running state
						api.Infrap4d.SetRunning()
						break
					}
					time.Sleep(m.conf.Infrap4dTimeout * time.Second)
				}
			}
			time.Sleep(m.conf.Infrap4dTimeout * time.Second)
		}
	}
}

func infrap4dRunning() bool {
	str := "ps ax | grep infrap4d | grep -v grep"
	out, err := exec.Command("bash", "-c", str).Output()
	if err != nil || len(out) == 0 {
		return false
	}
	return true
}

func (m *Manager) reconnectInfrap4d() bool {
	ctx := context.Background()

	if m.conf.P4BinPath == "" || m.conf.P4InfoPath == "" {
		log.Fatalf("Missing .bin or P4Info")
		os.Exit(1)
	}

	p4InfoPath, err := filepath.Abs(m.conf.P4InfoPath)
	if err != nil {
		log.Fatalf("Failed to get absolute representation of path %s",
			m.conf.P4InfoPath)
		os.Exit(1)
	}
	p4BinPath, err := filepath.Abs(m.conf.P4BinPath)
	if err != nil {
		log.Fatalf("Failed to get absolute representation of path %s",
			m.conf.P4BinPath)
		os.Exit(1)
	}

	if err := api.OpenP4RtC(ctx, 0, 1, m.conf.StopCh, *m.conf); err != nil {
		log.Errorf("Failed to open p4 runtime client connection")
		return false
	}

	if err := api.OpenGNMICCon(*m.conf); err != nil {
		log.Errorf("Failed to open gNMI client connection")
		return false
	}

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
	} else {
		// Setting fwding pipeline
		log.Infof("Setting the pipeline")

		if _, err := api.SetFwdPipe(ctx, p4BinPath, p4InfoPath,
			0); err != nil {
			log.Errorf("Error when setting forwarding pipe, err: %v", err)
			api.CloseP4RtCCon()
			api.CloseGNMIConn()
			return false
		}
	}

	return true
}

func Run(waitCh chan<- struct{}) {

	// Start the api server
	manager.createAndStartServer()

	// Insert the default rule for the arp-proxy
	api.InsertDefaultRule()

	/*
		Start a go routine to periodically check
		for the infrap4d server status
	*/
	go manager.Infrap4dStatusCheck()

	<-manager.conf.StopCh

	manager.stopServer()
	store.SyncDB()

	close(waitCh)

}
