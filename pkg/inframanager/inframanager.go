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
	"io"
	"os"
	"path"

	api "github.com/ipdk-io/k8s-infra-offload/inframanager/api_handler"
	"github.com/ipdk-io/k8s-infra-offload/pkg/inframanager/store"
	"github.com/ipdk-io/k8s-infra-offload/pkg/utils"
	"gopkg.in/tomb.v2"

	log "github.com/sirupsen/logrus"
)

const (
	logDir = "/var/log"
)

func logInit() {
	logFilename := path.Join(logDir, path.Base(os.Args[0])+".log")
	verifiedFileName, err := utils.VerifiedFilePath(logFilename, logDir)
	if err != nil {
		panic(err)
	}
	logFile, err := os.OpenFile(verifiedFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	mw := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(mw)

	switch api.GetLogLevel() {
	case "Panic":
		log.SetLevel(log.PanicLevel)
	case "Fatal":
		log.SetLevel(log.FatalLevel)
	case "Error":
		log.SetLevel(log.ErrorLevel)
	case "Warn":
		log.SetLevel(log.WarnLevel)
	case "Info":
		log.SetLevel(log.InfoLevel)
	case "Debug":
		log.SetLevel(log.DebugLevel)
	case "Trace":
		log.SetLevel(log.TraceLevel)
	default:
		log.SetLevel(log.DebugLevel)
	}

	log.SetReportCaller(true)
	log.SetFormatter(&log.TextFormatter{
		PadLevelText:     true,
		QuoteEmptyFields: true,
	})
}

type Manager struct {
	server *api.ApiServer
	log    *log.Entry
	t      tomb.Tomb
}

var manager *Manager

func NewManager() {
	logInit()
	manager = &Manager{
		log: log.WithField("pkg", "inframanager"),
	}
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

	store.RunSyncEndPointInfo()
	store.RunSyncServiceInfo()

	close(waitCh)
}
