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

package cni

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/ipdk-io/k8s-infra-offload/pkg/netconf"
	"github.com/ipdk-io/k8s-infra-offload/pkg/types"
	"github.com/ipdk-io/k8s-infra-offload/pkg/utils"
	pb "github.com/ipdk-io/k8s-infra-offload/proto"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	healthgrpc "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"gopkg.in/tomb.v2"
)

const (
	CNIServerSocket = "/var/run/calico/cni-server.sock"
)

// infra-agent Server information.
type CniServer struct {
	grpc             *grpc.Server
	listener         net.Listener
	log              *log.Entry
	name             string
	podInterfaceType string
	podInterface     types.PodInterface
	serveFunc        func() error
}

var (
	newPodInterface     = netconf.NewPodInterface
	getCredentialFunc   = utils.GetClientCredentials
	grpcDial            = grpc.Dial
	newInfraAgentClient = pb.NewInfraAgentClient

	listenFunc = net.Listen
	getNSFunc  = ns.GetNS
)

func NewCniServer(log *log.Entry, t, uri string, serveFunc func() error) (types.Server, error) {
	listen, err := listenFunc(types.ServerNetProto, uri)
	if err != nil {
		log.WithError(err).Error("failed to listen on socket")
		return nil, err
	}
	log.Infof("Listen on addr: %s", listen.Addr().String())
	kp := grpc.KeepaliveParams(keepalive.ServerParameters{MaxConnectionAge: time.Duration(time.Second * 10), MaxConnectionAgeGrace: time.Duration(time.Second * 30)})

	pi, err := newPodInterface(t, log.WithField("pkg", "netconf"))
	if err != nil {
		return nil, err
	}
	server := &CniServer{
		grpc:             grpc.NewServer(kp),
		listener:         listen,
		log:              log,
		name:             "cni-server",
		podInterfaceType: t,
		podInterface:     pi,
		serveFunc:        serveFunc,
	}

	if server.serveFunc == nil {
		server.serveFunc = server.serve
	}

	healthgrpc.RegisterHealthServer(server.grpc, server)
	pb.RegisterCniDataplaneServer(server.grpc, server)
	return server, nil
}

func (s *CniServer) GetName() string {
	return s.name
}

func (s *CniServer) Start(t *tomb.Tomb) error {
	errCh := make(chan error)
	go func() {
		if err := s.serveFunc(); err != nil {
			s.log.WithError(err).Error("error occur")
			errCh <- err
		}
	}()
	// block until dying on parent tomb

	select {
	case err := <-errCh:
		// an error in gRPC serve
		s.log.WithError(err).Error("An error occur")
		return err
	case <-t.Dying():
		s.log.Infof("CNI server receive Stop")
		s.StopServer()
		return nil
	}

}

func (s *CniServer) serve() error {
	s.log.Info("Serving CNI gRPC")
	types.CNIServerStatus = types.ServerStatusOK
	return s.grpc.Serve(s.listener)
}

func (s *CniServer) StopServer() {
	s.grpc.GracefulStop()
	s.listener.Close()
	types.CNIServerStatus = types.ServerStatusStopped
}

func (s *CniServer) Add(ctx context.Context, in *pb.AddRequest) (*pb.AddReply, error) {
	s.log.Infof("CNI Add request:%s", in.String())

	out := &pb.AddReply{Successful: false}
	intfInfo, err := s.podInterface.CreatePodInterface(in)
	if err != nil {
		out.ErrorMessage = err.Error()
		return out, nil
	}
	managerAddr := fmt.Sprintf("%s:%s", types.InfraManagerAddr, types.InfraManagerPort)
	credentials, err := getCredentialFunc()
	if err != nil {
		s.log.WithError(err).Error("error getting gRPC client credentials to connect to backend")
		return out, nil
	}
	conn, err := grpcDial(managerAddr, grpc.WithTransportCredentials(credentials))
	defer grpcClose(conn, s.log, "failed to close connnection, not fatal")

	if err != nil {
		out.ErrorMessage = err.Error()
		return out, nil
	}
	c := newInfraAgentClient(conn)

	in.DesiredHostInterfaceName = intfInfo.InterfaceName

	mgrRply, err := s.podInterface.SetupNetwork(ctx, c, intfInfo, in)
	if err != nil || !mgrRply.Successful {
		// We should release allocated interface here on error
		s.log.WithError(err).Error("Failed to configure interface via infra-manager, releasing allocated Pod interface")
		_ = s.podInterface.ReleasePodInterface(&pb.DelRequest{Netns: in.Netns, InterfaceName: in.InterfaceName})
		out.ErrorMessage = "Failed to configure interface via infra-manager CNI service"
		return out, err
	}

	// Everything went okay, set required fields for calico AddReply
	out.ContainerMac = intfInfo.MacAddr
	out.HostInterfaceName = in.DesiredHostInterfaceName
	out.Successful = true

	return out, err
}

func (s *CniServer) Del(ctx context.Context, in *pb.DelRequest) (*pb.DelReply, error) {
	logger := log.WithField("func", "Del")
	logger.Infof("CNI Del request: %v netns %s", in.String(), in.GetNetns())
	out := &pb.DelReply{
		Successful: true,
	}

	// Check if delete request came with empty netns
	netNs, netNsErr := getNSFunc(in.Netns)
	if netNs != nil {
		_ = netNs.Close()
	}
	if netNsErr != nil {
		_, ok := netNsErr.(ns.NSPathNotExistErr)
		if ok {
			s.log.WithError(netNsErr).Infof("Netns '%s' does not exist", in.Netns)
			// namespace already gone do not return error
			return out, nil
		}
	}

	managerAddr := fmt.Sprintf("%s:%s", types.InfraManagerAddr, types.InfraManagerPort)
	credentials, err := getCredentialFunc()
	if err != nil {
		s.log.WithError(err).Error("error getting gRPC client credentials to connect to backend")
		return out, nil
	}
	conn, err := grpcDial(managerAddr, grpc.WithTransportCredentials(credentials))
	defer grpcClose(conn, s.log, "failed to close connnection")

	if err != nil {
		out.Successful = false
		out.ErrorMessage = err.Error()
		return out, nil
	}

	c := newInfraAgentClient(conn)
	out, err = s.podInterface.ReleaseNetwork(ctx, c, in)
	if err != nil || !out.Successful {
		s.log.WithError(err).Error("Failed to clean up interface config via infra-manager")
	}

	_ = s.podInterface.ReleasePodInterface(in)

	if s.podInterfaceType != types.IpvlanPodInterface {
		netconf.DeletePodIfaceConf(in.InterfaceName, s.podInterfaceType, in.Netns)
	}

	return out, err
}

// Check is used to check the status of GRPC service
func (s *CniServer) Check(ctx context.Context, in *healthgrpc.HealthCheckRequest) (*healthgrpc.HealthCheckResponse, error) {
	if types.CNIServerStatus != types.ServerStatusOK {
		return &healthgrpc.HealthCheckResponse{Status: healthgrpc.HealthCheckResponse_NOT_SERVING}, errors.New("CNI server is not serving")
	}
	return &healthgrpc.HealthCheckResponse{Status: healthgrpc.HealthCheckResponse_SERVING}, nil
}

// Watch was created to fulfil interface requirements, unused
func (s *CniServer) Watch(in *healthgrpc.HealthCheckRequest, _ healthgrpc.Health_WatchServer) error {
	return errors.New("Unimplemented")
}

func grpcClose(conn *grpc.ClientConn, log *log.Entry, errorMsg string) {
	if conn == nil {
		return
	}
	if err := conn.Close(); err != nil {
		log.WithError(err).Error(errorMsg)
	}
}
