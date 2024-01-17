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
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"gopkg.in/tomb.v2"

	log "github.com/sirupsen/logrus"
)

const (
	logDir = "/var/log/inframanager"
)

type Manager struct {
	server   *api.ApiServer
	conf     *config.Configuration
	log      *log.Entry
	infrap4d *utils.ServerStatus
	t        tomb.Tomb
}

var manager *Manager

func NewManager(conf *config.Configuration) {
	err := utils.LogInit(logDir, api.GetLogLevel())
	if err != nil {
		return
	}
	utils.CreateCipherMap()
	api.NewApiServer()

	manager = &Manager{
		log:      log.WithField("pkg", "inframanager"),
		conf:     conf,
		infrap4d: utils.NewServerStatus(),
	}
	mgrAddr := viper.GetString("InfraManager.Addr")
	values := strings.Split(mgrAddr, ":")
	types.InfraManagerAddr = values[0]
	types.InfraManagerPort = values[1]
}

func (m *Manager) createAndStartServer() {
	m.server = api.CreateServer(m.conf, m.infrap4d, m.log)
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
			// Dial in to infrap4d grpc server
			conn, err := utils.GrpcDial(m.conf.Infrap4dGrpcServer.Addr,
				utils.GetConnType(m.conf.Infrap4dGrpcServer.Conn), utils.Infrap4dGrpcServer)
			defer func() {
				if conn == nil {
					return
				}
				if err := conn.Close(); err != nil {
					logger.Errorf("failed to close connection to infrap4d")
				}
			}()
			if err != nil {
				logger.Errorf("Cannot connect to infrap4d: %v, reconnecting..", err)
				// Let api server know that the infrap4d is not running
				m.infrap4d.SetStopped()
				//Try reconnecting to infrap4d
				m.reconnectInfrap4d()
				//Reprogram all rules
				m.server.ReplayRules()
				continue
			}

			// Check for infrap4d server status
			resp, err := healthpb.NewHealthClient(conn).Check(context.Background(),
				&healthpb.HealthCheckRequest{Service: ""})
			if err != nil {
				logger.Errorf("Cannot perform health check on infrap4d: %v, reconnecting..", err)
				// Let api server know that the infrap4d is not running
				m.infrap4d.SetStopped()
				//Try reconnecting to infrap4d
				m.reconnectInfrap4d()
				//Reprogram all rules
				m.server.ReplayRules()
				continue
			}
			/*
				Infrap4d is responding. Wait for a timeout and periodically check the
				connection status
			*/
			if resp.Status == healthpb.HealthCheckResponse_SERVING {

				/*
					Infrap4d is running.
					Check and set infrap4d to running state so that
					the api server is aware
				*/
				if !m.infrap4d.Running() {
					m.infrap4d.SetRunning()
				}

				time.Sleep(m.conf.Infrap4dTimeout * time.Second)
			} else {
				logger.Errorf("Infrap4d is not in the serving state, wait and reconnect..: %v", err)
				// Let api server know that the infrap4d is not running
				m.infrap4d.SetStopped()
				//Try reconnecting to infrap4d
				m.reconnectInfrap4d()
				//Reprogram all rules
				m.server.ReplayRules()
			}
		}
	}
}

func (m *Manager) reconnectInfrap4d() {
	ctx := context.Background()
	if m.conf.P4BinPath == "" || m.conf.P4InfoPath == "" {
		log.Fatalf("Missing .bin or P4Info")
		os.Exit(1)
	}

	p4InfoPath, err := filepath.Abs(m.conf.P4InfoPath)
	if err != nil {
		log.Fatalf("Failed to get absolute representation of path %s",
			m.conf.P4InfoPath)
	}
	p4BinPath, err := filepath.Abs(m.conf.P4BinPath)
	if err != nil {
		log.Fatalf("Failed to get absolute representation of path %s",
			m.conf.P4BinPath)
	}

	if err := api.OpenP4RtC(ctx, 0, 1, m.conf.StopCh); err != nil {
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
	} else {
		// Setting fwding pipeline
		log.Infof("Setting the pipeline")

		if _, err := api.SetFwdPipe(ctx, p4BinPath, p4InfoPath,
			0); err != nil {
			log.Errorf("Error when setting forwarding pipe, err: %v", err)
			api.CloseP4RtCCon()
			api.CloseGNMIConn()
			os.Exit(1)
		}
	}
}

func Run(waitCh chan<- struct{}) {

	// Insert the default rule for the arp-proxy
	api.InsertDefaultRule()

	// Start the api server
	manager.createAndStartServer()

	/*
		Start a go routine to periodically check
		for the infrap4d server status
	*/
	go manager.Infrap4dStatusCheck()

	<-manager.conf.StopCh

	manager.stopServer()
	store.SyncDB()

	//if !manager.restart() {
	close(waitCh)
	//}

}
