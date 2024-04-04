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

package infraagent

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/ipdk-io/k8s-infra-offload/pkg/cni"
	healthserver "github.com/ipdk-io/k8s-infra-offload/pkg/health_server"
	"github.com/ipdk-io/k8s-infra-offload/pkg/policy"
	"github.com/ipdk-io/k8s-infra-offload/pkg/services"
	"github.com/ipdk-io/k8s-infra-offload/pkg/types"
	"github.com/ipdk-io/k8s-infra-offload/pkg/utils"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
	"k8s.io/client-go/kubernetes"
)

type Agent interface {
	Run()
}

func NewAgent(intfType string, logLevel string, ifName string, logDir string, client kubernetes.Interface) (Agent, error) {
	err := utils.LogInit(logDir, logLevel)
	if err != nil {
		return nil, err
	}
	agent := &agent{
		client:           client,
		log:              log.WithField("pkg", "infraagent"),
		podInterfaceType: intfType,
		nodeIntf:         ifName,
	}
	return agent, nil
}

type agent struct {
	client           kubernetes.Interface
	log              *log.Entry
	podInterfaceType string
	nodeIntf         string
	t                tomb.Tomb
}

func (a *agent) startServer(serverName string, f func(t *tomb.Tomb) error) error {
	var err error
	a.t.Go(func() error {
		err = f(&a.t)
		if err != nil {
			a.log.Warnf("an error occur during starting server %s : %s", serverName, err)
			// t:Tomb will implicitly call t.Kill(err) to signal other go routines it's Dying.
			a.log.Warnf("Killing any other already running servers")
		}
		return err
	})

	return err
}

func (a *agent) prepareServers() ([]types.Server, error) {
	servers := []types.Server{}
	agentAddr := fmt.Sprintf("%s:%s", types.InfraAgentAddr, types.InfraAgentPort)

	cs, err := cni.NewCniServer(a.log.WithField("pkg", "cni"), a.podInterfaceType, agentAddr, nil)
	if err != nil {
		return nil, err
	}
	servers = append(servers, cs)

	srv, err := services.NewServiceServer(a.log.WithField("pkg", "services"), services.NewNatServiceHandler(a.log.WithField("pkg", "services")), types.ServiceRefreshTimeInSeconds)
	if err != nil {
		return nil, err
	}
	servers = append(servers, srv)

	p, err := policy.NewPolicyServer(a.log.WithField("pkg", "policy"))
	if err != nil {
		return nil, err
	}
	servers = append(servers, p)

	hs, err := healthserver.NewHealthCheckServer(a.log.WithField("pkg", "healthserver"))
	if err != nil {
		return nil, err
	}
	servers = append(servers, hs)

	return servers, nil
}

func (a *agent) startServers(servers []types.Server) error {
	for _, server := range servers {
		if err := a.startServer(server.GetName(), server.Start); err != nil {
			return err
		}
	}
	return nil
}

func (a *agent) stopServers() {
	a.t.Kill(fmt.Errorf("%s", "Stopping all servers"))
	_ = a.t.Wait()
}

func (a *agent) setConfig() error {
	logger := a.log.WithField("func", "agent.setConfig")

	if types.NodeName == "" {
		return errors.New("Cannot get node's name - NODE_NAME env variable is possibly empty")
	}

	if a.nodeIntf == "" {
		// discover node interface
		a.log.Infof("node interface is not specified, trying to discover node interface")
		interfaceGetter := utils.DefaultInterfaceAddressGetter{}
		iface, err := utils.GetNodeNetInterface(a.client, types.NodeName, &interfaceGetter, a.log)
		if err != nil {
			return fmt.Errorf("Failed to get node interface: %w", err)
		}
		a.nodeIntf = iface
	}
	types.NodeInterfaceName = a.nodeIntf

	// fetch Pods CIDR from k8s api-server
	podsCidr, err := utils.GetNodePodsCIDR(a.client, types.NodeName)
	if err != nil {
		return err
	}
	types.NodePodsCIDR = podsCidr

	logger.Infof("pods cidr: %s node interface name %s", types.NodePodsCIDR, types.NodeInterfaceName)
	if err := utils.GetSubnets(a.client); err != nil {
		return err
	}
	logger.Infof("cluster pods ip: %s service subnet %s", types.ClusterPodsCIDR, types.ClusterServicesSubnet)
	return nil
}

func (a *agent) Run() {
	logger := a.log.WithField("func", "agent.Run")

	logger.Infof("Starting agent with interfaceType: %s and node interface: %s", a.podInterfaceType, a.nodeIntf)

	signalChannel := make(chan os.Signal, 2)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)

	if err := a.setConfig(); err != nil {
		logger.WithError(err).Fatal("Failed to get cluster configuration")
	}

	servers, err := a.prepareServers()
	if err != nil {
		log.Errorf("failed to initialize one or more server(s): %s", err)
		os.Exit(1)
	}

	if err := a.startServers(servers); err != nil {
		log.Errorf("failed to start one or more server(s): %s", err)
		os.Exit(2)
	}

	<-signalChannel
	logger.Infof("SIGINT received, exiting")
	a.stopServers()
}
