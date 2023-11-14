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
	"fmt"
	"strings"

	api "github.com/ipdk-io/k8s-infra-offload/inframanager/api_handler"
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
	log    *log.Entry
	t      tomb.Tomb
}

var manager *Manager

func NewManager() {
	err := utils.LogInit(logDir, api.GetLogLevel())
	if err != nil {
		return
	}
	utils.CreateCipherMap()
	api.NewApiServer()

	manager = &Manager{
		log: log.WithField("pkg", "inframanager"),
	}
	mgrAddr := viper.GetString("InfraManager.Addr")
	values := strings.Split(mgrAddr, ":")
	types.InfraManagerAddr = values[0]
	types.InfraManagerPort = values[1]
}

func (m *Manager) createAndStartServer() {
	m.server = api.CreateServer(m.log)
	m.server.Start(&m.t)
}

func (m *Manager) stopServer() {
	m.t.Kill(fmt.Errorf("%s", "Stopping server"))
	if err := m.t.Wait(); err != nil {
		log.Errorf("stop server error %s", err)
	}
}

func Run(stopCh <-chan struct{}, waitCh chan<- struct{}) {

	// Insert the default rule for the arp-proxy
	api.InsertDefaultRule()

	// Start the api server
	manager.createAndStartServer()

	<-stopCh

	manager.stopServer()
	store.SyncDB()

	close(waitCh)

}
