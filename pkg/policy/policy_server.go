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

package policy

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/ipdk-io/k8s-infra-offload/pkg/types"
	"github.com/ipdk-io/k8s-infra-offload/pkg/utils"
	pb "github.com/ipdk-io/k8s-infra-offload/proto"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"gopkg.in/tomb.v2"
)

var (
	grpcDial              = grpc.Dial
	getCredentialFunc     = utils.GetClientCredentials
	pbNewInfraAgentClient = pb.NewInfraAgentClient
	cancellableListener   = getCancellableListener
	removeSocket          = os.RemoveAll
)

type PolicyServer struct {
	log           *logrus.Entry
	nextSeqNumber uint64
	exiting       chan bool
	name          string
}

func NewPolicyServer(log *logrus.Entry) (types.Server, error) {
	return &PolicyServer{
		log:           log,
		nextSeqNumber: 0,
		exiting:       make(chan bool),
		name:          "felix-policy-server"}, nil
}

func (s *PolicyServer) GetName() string {
	return s.name
}

func (s *PolicyServer) SyncPolicy(conn net.Conn) {
	for {
		msg, err := s.RecvMessage(conn)
		if err != nil {
			s.log.WithError(err).Warn("error communicating with felix")
			conn.Close()
			return
		}
		s.log.Infof("Got message from felix %T", msg)
		switch m := msg.(type) {
		case *pb.ConfigUpdate:
			err = s.handleConfigUpdate(m)
		case *pb.InSync:
			err = s.handleInSyc(m)
		default:
			err = s.handleMessage(msg, false)
		}

		if err != nil {
			s.log.WithError(err).Warn("Error processing update from felix, restarting")
			conn.Close()
			return
		}

	}
}

func (s *PolicyServer) handleMessage(msg interface{}, pending bool) error {
	switch m := msg.(type) {
	case *pb.IPSetUpdate:
		return s.handleIpsetUpdate(m, pending)
	case *pb.IPSetDeltaUpdate:
		return s.handleIpsetDeltaUpdate(m, pending)
	case *pb.IPSetRemove:
		return s.handleIpsetRemove(m, pending)
	case *pb.ActivePolicyUpdate:
		return s.handleActivePolicyUpdate(m, pending)
	case *pb.ActivePolicyRemove:
		return s.handleActivePolicyRemove(m, pending)
	case *pb.ActiveProfileUpdate:
		return s.handleActiveProfileUpdate(m, pending)
	case *pb.ActiveProfileRemove:
		return s.handleActiveProfileRemove(m, pending)
	case *pb.HostEndpointUpdate:
		return s.handleHostEndpointUpdate(m, pending)
	case *pb.HostEndpointRemove:
		return s.handleHostEndpointRemove(m, pending)
	case *pb.WorkloadEndpointUpdate:
		return s.handleWorkloadEndpointUpdate(m, pending)
	case *pb.WorkloadEndpointRemove:
		return s.handleWorkloadEndpointRemove(m, pending)
	case *pb.HostMetadataUpdate:
		return s.handleHostMetadataUpdate(m, pending)
	case *pb.HostMetadataRemove:
		return s.handleHostMetadataRemove(m, pending)
	case *pb.IPAMPoolUpdate:
		return s.handleIpamPoolUpdate(m, pending)
	case *pb.IPAMPoolRemove:
		return s.handleIpamPoolRemove(m, pending)
	case *pb.ServiceAccountUpdate:
		return s.handleServiceAccountUpdate(m, pending)
	case *pb.ServiceAccountRemove:
		return s.handleServiceAccountRemove(m, pending)
	case *pb.NamespaceUpdate:
		return s.handleNamespaceUpdate(m, pending)
	case *pb.NamespaceRemove:
		return s.handleNamespaceRemove(m, pending)
	case *pb.RouteUpdate:
		return s.handleRouteUpdate(m, pending)
	case *pb.RouteRemove:
		return s.handleRouteRemove(m, pending)
	case *pb.VXLANTunnelEndpointRemove:
		return s.handleVXLANTunnelEndpointRemove(m, pending)
	case *pb.VXLANTunnelEndpointUpdate:
		return s.handleVXLANTunnelEndpointUpdate(m, pending)
	case *pb.WireguardEndpointUpdate:
		return s.handleWireguardEndpointUpdate(m, pending)
	case *pb.WireguardEndpointRemove:
		return s.handleWireguardEndpointRemove(m, pending)
	case *pb.GlobalBGPConfigUpdate:
		return s.handleGlobalBGPConfigUpdate(m, pending)
	default:
		s.log.Warnf("Unhandled message from felix: %v", m)
	}
	return nil
}

func (s *PolicyServer) StopServer() {
	s.exiting <- true
}

// Not needed?
func (s *PolicyServer) handleConfigUpdate(msg *pb.ConfigUpdate) error {
	s.log.Infof("Got config update %+v", msg)
	return nil
}

// Not needed?
func (s *PolicyServer) handleInSyc(msg *pb.InSync) error {
	s.log.Infof("Got in sync %+v", msg)
	return nil
}

func (s *PolicyServer) handleIpsetUpdate(msg *pb.IPSetUpdate, pending bool) error {
	s.log.Infof("Got ipset update %+v pending %v", msg, pending)
	out := &pb.Reply{
		Successful: true,
	}
	c, err := s.dialManager()
	if err != nil {
		return errors.Wrap(err, "cannot process handleIpsetUpdate: cannot dial manager")
	}
	// TODO: Add pending flag
	out, err = c.UpdateIPSet(context.TODO(), msg)
	if err != nil || !out.Successful {
		return errors.Wrap(err, "cannot process handleIpsetUpdate")
	}
	return nil
}

func (s *PolicyServer) handleIpsetDeltaUpdate(msg *pb.IPSetDeltaUpdate, pending bool) error {
	s.log.Infof("Got ipset delta update %+v, pending %v", msg, pending)
	out := &pb.Reply{
		Successful: true,
	}
	c, err := s.dialManager()
	if err != nil {
		return errors.Wrap(err, "cannot process handleIpsetDeltaUpdate: cannot dial manager")
	}
	// TODO: Add pending flag
	out, err = c.UpdateIPSetDelta(context.TODO(), msg)
	if err != nil || !out.Successful {
		return errors.Wrap(err, "cannot process handleIpsetDeltaUpdate")
	}
	return nil
}

func (s *PolicyServer) handleIpsetRemove(msg *pb.IPSetRemove, pending bool) error {
	s.log.Infof("Got ipset remove %+v, pending %v", msg, pending)
	out := &pb.Reply{
		Successful: true,
	}
	c, err := s.dialManager()
	if err != nil {
		return errors.Wrap(err, "cannot process handleIpsetRemove: cannot dial manager")
	}
	// TODO: Add pending flag
	out, err = c.RemoveIPSet(context.TODO(), msg)
	if err != nil || !out.Successful {
		return errors.Wrap(err, "cannot process handleIpsetRemove")
	}
	return nil
}

func (s *PolicyServer) handleActivePolicyUpdate(msg *pb.ActivePolicyUpdate, pending bool) error {
	s.log.Infof("Got active police update %+v, pending %v", msg, pending)
	out := &pb.Reply{
		Successful: true,
	}
	c, err := s.dialManager()
	if err != nil {
		return errors.Wrap(err, "cannot process handleActivePolicyUpdate: cannot dial manager")
	}
	// TODO: Add pending flag
	out, err = c.ActivePolicyUpdate(context.TODO(), msg)
	if err != nil || !out.Successful {
		return errors.Wrap(err, "cannot process handleActivePolicyUpdate")
	}
	return nil
}

func (s *PolicyServer) handleActivePolicyRemove(msg *pb.ActivePolicyRemove, pending bool) error {
	s.log.Infof("Got active police remove %+v, pending %v", msg, pending)
	out := &pb.Reply{
		Successful: true,
	}
	c, err := s.dialManager()
	if err != nil {
		return errors.Wrap(err, "cannot process handleActivePolicyRemove: cannot dial manager")
	}
	// TODO: Add pending flag
	out, err = c.ActivePolicyRemove(context.TODO(), msg)
	if err != nil || !out.Successful {
		return errors.Wrap(err, "cannot process handleActivePolicyRemove")
	}
	return nil
}

func (s *PolicyServer) handleActiveProfileUpdate(msg *pb.ActiveProfileUpdate, pending bool) error {
	s.log.Infof("Got active profile update %+v, pending %v", msg, pending)
	out := &pb.Reply{
		Successful: true,
	}
	c, err := s.dialManager()
	if err != nil {
		return errors.Wrap(err, "cannot process handleActiveProfileUpdate: cannot dial manager")
	}
	// TODO: Add pending flag
	out, err = c.UpdateActiveProfile(context.TODO(), msg)
	if err != nil || !out.Successful {
		return errors.Wrap(err, "cannot process handleActiveProfileUpdate")
	}
	return nil
}

func (s *PolicyServer) handleActiveProfileRemove(msg *pb.ActiveProfileRemove, pending bool) error {
	s.log.Infof("Got active profile remove %+v, pending %v", msg, pending)
	out := &pb.Reply{
		Successful: true,
	}
	c, err := s.dialManager()
	if err != nil {
		return errors.Wrap(err, "cannot process handleActiveProfileRemove: cannot dial manager")
	}
	// TODO: Add pending flag
	out, err = c.RemoveActiveProfile(context.TODO(), msg)
	if err != nil || !out.Successful {
		return errors.Wrap(err, "cannot process handleActiveProfileRemove")
	}
	return nil
}

func (s *PolicyServer) handleHostEndpointUpdate(msg *pb.HostEndpointUpdate, pending bool) error {
	s.log.Infof("Got host endpoint update %+v, pending %v", msg, pending)
	out := &pb.Reply{
		Successful: true,
	}
	c, err := s.dialManager()
	if err != nil {
		return errors.Wrap(err, "cannot process handleHostEndpointUpdate: cannot dial manager")
	}
	// TODO: Add pending flag
	out, err = c.UpdateHostEndpoint(context.TODO(), msg)
	if err != nil || !out.Successful {
		return errors.Wrap(err, "cannot process handleHostEndpointUpdate")
	}
	return nil
}

func (s *PolicyServer) handleHostEndpointRemove(msg *pb.HostEndpointRemove, pending bool) error {
	s.log.Infof("Got host endpoint remove %+v, pending %v", msg, pending)
	out := &pb.Reply{
		Successful: true,
	}
	c, err := s.dialManager()
	if err != nil {
		return errors.Wrap(err, "cannot process handleHostEndpointRemove: cannot dial manager")
	}
	// TODO: Add pending flag
	out, err = c.RemoveHostEndpoint(context.TODO(), msg)
	if err != nil || !out.Successful {
		return errors.Wrap(err, "cannot process handleHostEndpointRemove")
	}
	return nil
}

func (s *PolicyServer) handleWorkloadEndpointUpdate(msg *pb.WorkloadEndpointUpdate, pending bool) error {
	s.log.Infof("Got workload endpoint update %+v, pending %v", msg, pending)
	out := &pb.Reply{
		Successful: true,
	}
	c, err := s.dialManager()
	if err != nil {
		return errors.Wrap(err, "cannot process handleWorkloadEndpointUpdate: cannot dial manager")
	}
	// TODO: Add pending flag
	out, err = c.UpdateLocalEndpoint(context.TODO(), msg)
	if err != nil || !out.Successful {
		return errors.Wrap(err, "cannot process handleWorkloadEndpointUpdate")
	}
	return nil
}

func (s *PolicyServer) handleWorkloadEndpointRemove(msg *pb.WorkloadEndpointRemove, pending bool) error {
	s.log.Infof("Got workload endpoint remove %+v, pending %v", msg, pending)
	out := &pb.Reply{
		Successful: true,
	}
	c, err := s.dialManager()
	if err != nil {
		return errors.Wrap(err, "cannot process handleWorkloadEndpointRemove: cannot dial manager")
	}
	// TODO: Add pending flag
	out, err = c.RemoveLocalEndpoint(context.TODO(), msg)
	if err != nil || !out.Successful {
		return errors.Wrap(err, "cannot process handleWorkloadEndpointRemove")
	}
	return nil
}

func (s *PolicyServer) handleHostMetadataUpdate(msg *pb.HostMetadataUpdate, pending bool) error {
	s.log.Infof("Got host metadata update %+v, pending %v", msg, pending)
	out := &pb.Reply{
		Successful: true,
	}
	c, err := s.dialManager()
	if err != nil {
		return errors.Wrap(err, "cannot process handleHostMetadataUpdate: cannot dial manager")
	}
	// TODO: Add pending flag
	out, err = c.UpdateHostMetaData(context.TODO(), msg)
	if err != nil || !out.Successful {
		return errors.Wrap(err, "cannot process handleHostMetadataUpdate")
	}
	return nil
}

func (s *PolicyServer) handleHostMetadataRemove(msg *pb.HostMetadataRemove, pending bool) error {
	s.log.Infof("Got host metadata remove %+v, pending %v", msg, pending)
	out := &pb.Reply{
		Successful: true,
	}
	c, err := s.dialManager()
	if err != nil {
		return errors.Wrap(err, "cannot process handleHostMetadataRemove: cannot dial manager")
	}
	// TODO: Add pending flag
	out, err = c.RemoveHostMetaData(context.TODO(), msg)
	if err != nil || !out.Successful {
		return errors.Wrap(err, "cannot process handleHostMetadataRemove")
	}
	return nil
}

// Not needed?
func (s *PolicyServer) handleIpamPoolUpdate(msg *pb.IPAMPoolUpdate, pending bool) error {
	s.log.Infof("Got ipam pool update %+v, pending %v", msg, pending)
	return nil
}

// Not needed?
func (s *PolicyServer) handleIpamPoolRemove(msg *pb.IPAMPoolRemove, pending bool) error {
	s.log.Infof("Got ipam pool remove %+v, pending %v", msg, pending)
	return nil
}

func (s *PolicyServer) handleServiceAccountUpdate(msg *pb.ServiceAccountUpdate, pending bool) error {
	s.log.Infof("Got service account update %+v, pending %v", msg, pending)
	out := &pb.Reply{
		Successful: true,
	}
	c, err := s.dialManager()
	if err != nil {
		return errors.Wrap(err, "cannot process handleServiceAccountUpdate: cannot dial manager")
	}
	// TODO: Add pending flag
	out, err = c.UpdateServiceAccount(context.TODO(), msg)
	if err != nil || !out.Successful {
		return errors.Wrap(err, "cannot process handleServiceAccountUpdate")
	}
	return nil
}

func (s *PolicyServer) handleServiceAccountRemove(msg *pb.ServiceAccountRemove, pending bool) error {
	s.log.Infof("Got service account remove %+v, pending %v", msg, pending)
	out := &pb.Reply{
		Successful: true,
	}
	c, err := s.dialManager()
	if err != nil {
		return errors.Wrap(err, "cannot process handleServiceAccountRemove: cannot dial manager")
	}
	// TODO: Add pending flag
	out, err = c.RemoveServiceAccount(context.TODO(), msg)
	if err != nil || !out.Successful {
		return errors.Wrap(err, "cannot process handleServiceAccountRemove")
	}
	return nil
}

func (s *PolicyServer) handleNamespaceUpdate(msg *pb.NamespaceUpdate, pending bool) error {
	s.log.Infof("Got namespace update %+v, pending %v", msg, pending)
	out := &pb.Reply{
		Successful: true,
	}
	c, err := s.dialManager()
	if err != nil {
		return errors.Wrap(err, "cannot process handleNamespaceUpdate: cannot dial manager")
	}
	// TODO: Add pending flag
	out, err = c.UpdateNamespace(context.TODO(), msg)
	if err != nil || !out.Successful {
		return errors.Wrap(err, "cannot process handleNamespaceUpdate")
	}
	return nil
}

func (s *PolicyServer) handleNamespaceRemove(msg *pb.NamespaceRemove, pending bool) error {
	s.log.Infof("Got namespace remove %+v, pending %v", msg, pending)
	out := &pb.Reply{
		Successful: true,
	}
	c, err := s.dialManager()
	if err != nil {
		return errors.Wrap(err, "cannot process handleNamespaceRemove: cannot dial manager")
	}
	// TODO: Add pending flag
	out, err = c.RemoveNamespace(context.TODO(), msg)
	if err != nil || !out.Successful {
		return errors.Wrap(err, "cannot process handleNamespaceRemove")
	}
	return nil
}

func (s *PolicyServer) handleRouteUpdate(msg *pb.RouteUpdate, pending bool) error {
	s.log.Infof("Got route update %+v, pending %v", msg, pending)
	out := &pb.Reply{
		Successful: true,
	}
	c, err := s.dialManager()
	if err != nil {
		return errors.Wrap(err, "cannot process handleRouteUpdate: cannot dial manager")
	}
	// TODO: Add pending flag
	out, err = c.UpdateRoute(context.TODO(), msg)
	if err != nil || !out.Successful {
		return errors.Wrap(err, "cannot process handleRouteUpdate")
	}
	return nil
}

func (s *PolicyServer) handleRouteRemove(msg *pb.RouteRemove, pending bool) error {
	s.log.Infof("Got route remove %+v, pending %v", msg, pending)
	out := &pb.Reply{
		Successful: true,
	}
	c, err := s.dialManager()
	if err != nil {
		return errors.Wrap(err, "cannot process handleRouteRemove: cannot dial manager")
	}
	// TODO: Add pending flag
	out, err = c.RemoveRoute(context.TODO(), msg)
	if err != nil || !out.Successful {
		return errors.Wrap(err, "cannot process handleRouteRemove")
	}
	return nil
}

func (s *PolicyServer) handleVXLANTunnelEndpointUpdate(msg *pb.VXLANTunnelEndpointUpdate, pending bool) error {
	s.log.Infof("Got VXLAN tunnel endpoint update %+v, pending %v", msg, pending)
	out := &pb.Reply{
		Successful: true,
	}
	c, err := s.dialManager()
	if err != nil {
		return errors.Wrap(err, "cannot process handleVXLANTunnelEndpointUpdate: cannot dial manager")
	}
	// TODO: Add pending flag
	out, err = c.UpdateVXLANTunnelEndpoint(context.TODO(), msg)
	if err != nil || !out.Successful {
		return errors.Wrap(err, "cannot process handleVXLANTunnelEndpointUpdate")
	}
	return nil
}

func (s *PolicyServer) handleVXLANTunnelEndpointRemove(msg *pb.VXLANTunnelEndpointRemove, pending bool) error {
	s.log.Infof("Got VXLAN tunnel endpoint remove %+v, pending %v", msg, pending)
	out := &pb.Reply{
		Successful: true,
	}
	c, err := s.dialManager()
	if err != nil {
		return errors.Wrap(err, "cannot process handleVXLANTunnelEndpointRemove: cannot dial manager")
	}
	// TODO: Add pending flag
	out, err = c.RemoveVXLANTunnelEndpoint(context.TODO(), msg)
	if err != nil || !out.Successful {
		return errors.Wrap(err, "cannot process handleVXLANTunnelEndpointRemove")
	}
	return nil
}

func (s *PolicyServer) handleWireguardEndpointUpdate(msg *pb.WireguardEndpointUpdate, pending bool) error {
	s.log.Infof("Got Wireguard endpoint update %+v, pending %v", msg, pending)
	return nil
}

func (s *PolicyServer) handleWireguardEndpointRemove(msg *pb.WireguardEndpointRemove, pending bool) error {
	s.log.Infof("Got Wireguard endpoint remove %+v, pending %v", msg, pending)
	return nil
}

func (s *PolicyServer) handleGlobalBGPConfigUpdate(msg *pb.GlobalBGPConfigUpdate, pending bool) error {
	s.log.Infof("Got GlobalBGPConfig update %+v, pending %v", msg, pending)
	return nil
}

func (s *PolicyServer) dialManager() (pb.InfraAgentClient, error) {
	managerAddr := fmt.Sprintf("%s:%s", types.InfraManagerAddr, types.InfraManagerPort)
	credentials, err := getCredentialFunc()
	if err != nil {
		return nil, fmt.Errorf("error getting gRPC client credentials to connect to backend: %s", err.Error())
	}
	conn, err := grpcDial(managerAddr, grpc.WithTransportCredentials(credentials))
	if err != nil {
		s.log.WithField("func", "dialManager")
		s.log.Errorf("unable to dial Infra Manager. err %v", err)
		return nil, err
	}
	return pbNewInfraAgentClient(conn), nil
}

func getCancellableListener(ctx context.Context) (net.Listener, error) {
	var lc net.ListenConfig
	return lc.Listen(ctx, "unix", types.FelixDataplaneSocket)
}

func (s *PolicyServer) Start(t *tomb.Tomb) error {
	s.log.Info("Starting policy server")
	_ = removeSocket(types.FelixDataplaneSocket)
	waitCh := make(chan struct{})
	ctx, cancel := context.WithCancel(context.TODO())
	listener, err := cancellableListener(ctx)
	if err != nil {
		s.log.WithError(err).Errorf("Could not bind to %s", types.FelixDataplaneSocket)
		cancel()
		return err
	}
	go func() {
		defer close(waitCh)
		<-ctx.Done()
		if listener != nil {
			listener.Close()
		}
		_ = removeSocket(types.FelixDataplaneSocket)
	}()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					// error due context cancelation
					return
				default:
					s.log.WithError(err).Warn("cannot accept policy connection")
					return
				}
			}
			go s.SyncPolicy(conn)

			s.log.Info("Waiting to close...")
			<-s.exiting
			if err = conn.Close(); err != nil {
				s.log.WithError(err).Error("error closing conection to felix API proxy")
			}
		}
	}()

	<-t.Dying()
	s.log.Info("Closing server...")
	close(s.exiting)
	cancel()
	//wait for cancel end
	<-waitCh

	s.log.Info("Policy server exited.")
	return nil
}
