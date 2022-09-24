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
	"io"
	"os"
	"path"

	api "github.com/ipdk-io/k8s-infra-offload/inframanager/api-handler"

	"github.com/antoninbas/p4runtime-go-client/pkg/signals"
	log "github.com/sirupsen/logrus"
)

const (
	logDir = "/var/log"
)

func logInit() {
	logFilename := path.Join(logDir, path.Base(os.Args[0])+".log")
	logFile, err := os.OpenFile(logFilename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	mw := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(mw)
	log.SetLevel(log.DebugLevel)
	log.SetReportCaller(true)
	log.SetFormatter(&log.TextFormatter{
		PadLevelText:     true,
		QuoteEmptyFields: true,
	})
}

type Manager struct {
	server *api.ApiServer
	log    *log.Entry
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
	m.server.Start()
}

func (m *Manager) stopServer() {
	m.server.Stop()
}

func Run() {
	signalChannel := signals.RegisterSignalHandlers()

	manager.createAndStartServer()

	<-signalChannel

	manager.stopServer()
}
