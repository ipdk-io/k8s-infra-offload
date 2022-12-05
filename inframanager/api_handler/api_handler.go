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

package api_handler

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ipdk-io/k8s-infra-offload/pkg/types"
	"github.com/ipdk-io/k8s-infra-offload/proto"
	"gopkg.in/tomb.v2"

	"github.com/antoninbas/p4runtime-go-client/pkg/client"
	conf "github.com/ipdk-io/k8s-infra-offload/pkg/inframanager/config"
	p4 "github.com/ipdk-io/k8s-infra-offload/pkg/inframanager/p4"
	"github.com/ipdk-io/k8s-infra-offload/pkg/inframanager/store"
	pb "github.com/ipdk-io/k8s-infra-offload/proto"

	p4_v1 "github.com/p4lang/p4runtime/go/p4/v1"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthgrpc "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
)

var config *conf.Configuration
var hostInterfaceMac string

func PutConf(c *conf.Configuration) {
	config = c
}

type ApiServer struct {
	listener   net.Listener
	grpc       *grpc.Server
	log        *log.Entry
	p4RtC      *client.Client
	p4RtCConn  *grpc.ClientConn
	gNMICConn  *grpc.ClientConn
	gNMIClient pb.GNMIClient
}

var api *ApiServer
var once sync.Once

func NewApiServer() *ApiServer {
	once.Do(func() {
		api = &ApiServer{}
	})
	return api
}

func OpenP4RtC(ctx context.Context, high uint64, low uint64, stopCh <-chan struct{}) error {
	var err error

	log.Infof("Connecting to P4Runtime Server at %s", config.Client.Addr)

	server := NewApiServer()

	server.p4RtCConn, err = grpc.Dial(config.Client.Addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Errorf("Cannot connect to P4Runtime Client: %v", err)
		return err
	}

	c := p4_v1.NewP4RuntimeClient(server.p4RtCConn)
	resp, err := c.Capabilities(ctx, &p4_v1.CapabilitiesRequest{})
	if err != nil {
		log.Errorf("Error in Capabilities RPC: %v", err)
		return err
	}
	log.Infof("P4Runtime server version is %s", resp.P4RuntimeApiVersion)

	electionID := p4_v1.Uint128{High: high, Low: low}
	//electionID := p4_v1.Uint128{High: 0, Low: 1}
	server.p4RtC = client.NewClient(c, config.DeviceId, &electionID)

	arbitrationCh := make(chan bool)
	waitCh := make(chan struct{})

	go server.p4RtC.Run(stopCh, arbitrationCh, nil)

	go func() {
		sent := false
		for isPrimary := range arbitrationCh {
			if isPrimary {
				log.Infof("We are the primary client!")
				if !sent {
					waitCh <- struct{}{}
					sent = true
				}
			} else {
				log.Errorf("We are not the primary client!")
			}
		}
	}()

	timeout := 5 * time.Second
	var cancel context.CancelFunc
	ctx2, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	select {
	case <-ctx2.Done():
		log.Errorf("Could not become the primary client within %v", timeout)
	case <-waitCh:
	}
	return err
}

func CloseP4RtCCon() {
	server := NewApiServer()
	if server.p4RtCConn != nil {
		server.p4RtCConn.Close()
	}
}

func OpenGNMICCon() error {
	var err error

	server := NewApiServer()

	server.gNMICConn, err = grpc.Dial(config.GNMIServer.Addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Errorf("Cannot connect to gNMI Server: %v", err)
		return err
	}

	server.gNMIClient = pb.NewGNMIClient(server.gNMICConn)
	return nil
}

func CloseGNMIConn() {
	server := NewApiServer()
	if server.gNMICConn != nil {
		server.gNMICConn.Close()
	}
}

func getPortID(ifName string) (portID uint32, err error) {
	var resp *pb.GetResponse

	if len(ifName) == 0 {
		err = fmt.Errorf("Empty interface name. Provide a valid input")
		return
	}

	req := &pb.GetRequest{
		Path: []*pb.Path{
			&pb.Path{
				Elem: []*pb.PathElem{
					&pb.PathElem{
						Name: "interfaces",
					},
					&pb.PathElem{
						Name: "virtual-interface",
						Key: map[string]string{
							"name": ifName,
						},
					},
					&pb.PathElem{
						Name: "config",
					},
					&pb.PathElem{
						Name: "tdi-portin-id",
					},
				},
			},
		},
		Type:     pb.GetRequest_ALL,
		Encoding: pb.Encoding_PROTO,
	}

	server := NewApiServer()
	if resp, err = server.gNMIClient.Get(context.Background(),
		req); err != nil {
		return
	}

	val := (resp.Notification[0].Update[0].Val.Value).(*pb.TypedValue_UintVal)
	portID = (uint32)(val.UintVal)
	return
}

func GetFwdPipe(ctx context.Context,
	responseType client.GetFwdPipeResponseType) (*client.FwdPipeConfig, error) {
	server := NewApiServer()
	return server.p4RtC.GetFwdPipe(ctx, responseType)
}

func SetFwdPipe(ctx context.Context, binPath string,
	p4InfoPath string, cookie uint64) (*client.FwdPipeConfig, error) {
	server := NewApiServer()
	return server.p4RtC.SetFwdPipe(ctx, binPath, p4InfoPath, cookie)
}

func CreateServer(log *log.Entry) *ApiServer {
	logger := log.WithField("func", "CreateAndStartServer")
	logger.Infof("Starting infra-manager gRPC server")

	managerAddr := fmt.Sprintf("%s:%s", types.InfraManagerAddr, types.InfraManagerPort)
	listen, err := net.Listen(types.ServerNetProto, managerAddr)
	if err != nil {
		logger.Fatalf("failed to listen on %s://%s, err: %v", types.ServerNetProto, managerAddr, err)
	}
	kp := grpc.KeepaliveParams(keepalive.ServerParameters{MaxConnectionAge: time.Duration(time.Second * 10), MaxConnectionAgeGrace: time.Duration(time.Second * 30)})

	server := NewApiServer()
	server.grpc = grpc.NewServer(kp)
	server.listener = listen
	server.log = log

	proto.RegisterInfraAgentServer(server.grpc, server)
	healthgrpc.RegisterHealthServer(server.grpc, server)
	logger.Infof("Infra Manager serving on %s://%s", types.ServerNetProto, managerAddr)
	return server
}

func InsertDefaultRule() {
	server := NewApiServer()
	p4.ArptToPortTable(context.Background(), server.p4RtC, types.DefaultRoute,
		types.ArpProxyDefaultPort, true)
}

func (s *ApiServer) Start(t *tomb.Tomb) {
	logger := s.log.WithField("func", "startServer")
	logger.Infof("Serving ApiServer gRPC")
	types.InfraManagerServerStatus = types.ServerStatusOK

	t.Go(func() error {
		errCh := make(chan error)

		go func() {
			err := s.grpc.Serve(s.listener)
			if err != nil {
				logger.Errorf("Failed to serve: %v", err)
				errCh <- err
			}
		}()

		select {
		case err := <-errCh:
			return err
		case <-t.Dying():
			logger.Infof("API Server received stop signal")
			s.Stop()
			return nil
		}
	})
}

func (s *ApiServer) Stop() {
	logger := s.log.WithField("func", "stopServer")
	logger.Infof("Stopping infra-manager gRPC server")
	s.grpc.GracefulStop()
	s.listener.Close()
	types.InfraManagerServerStatus = types.ServerStatusStopped
}

func insertRule(log *log.Entry, ctx context.Context, p4RtC *client.Client, macAddr string, ipAddr string, portID int, ifaceType p4.InterfaceType) (bool, error) {
	var err error

	logger := log.WithField("func", "insertRule")

	ep := store.EndPoint{
		PodIpAddress:  ipAddr,
		InterfaceID:   uint32(portID),
		PodMacAddress: macAddr,
	}

	entry := ep.GetFromStore()
	if entry != nil {
		epEntry := entry.(store.EndPoint)
		if epEntry.PodIpAddress == ep.PodIpAddress &&
			epEntry.InterfaceID == ep.InterfaceID &&
			epEntry.PodMacAddress == ep.PodMacAddress {

			logger.Infof("Entry %s %s %d already exists",
				macAddr, ipAddr, portID)
			return true, nil
		} else {
			err = fmt.Errorf("A different entry for %s already exists in the store", ipAddr)
			return false, err
		}
	}

	logger.Infof("Inserting entry into the cni tables")
	if err = p4.InsertCniRules(ctx, p4RtC, macAddr, ipAddr, portID, ifaceType); err != nil {
		logger.Errorf("Failed to insert the entries for %s %s", macAddr, ipAddr)
		return false, err
	}
	logger.Infof("Inserted the entries %s %s %d into the pipeline",
		macAddr, ipAddr, portID)

	if ep.WriteToStore() != true {
		err = fmt.Errorf("Failed to add %s %s %d to the store",
			macAddr, ipAddr, portID)
		return false, err
	}
	logger.Infof("Inserted the entries %s %s %d into the store",
		macAddr, ipAddr, portID)

	return true, err
}

func (s *ApiServer) CreateNetwork(ctx context.Context, in *proto.CreateNetworkRequest) (*proto.AddReply, error) {
	var err error

	logger := s.log.WithField("func", "CreateNetwork")
	logger.Infof("Incoming Add request %s", in.String())

	out := &proto.AddReply{
		HostInterfaceName: in.AddRequest.DesiredHostInterfaceName,
		Successful:        true,
	}

	server := NewApiServer()

	ipAddr := strings.Split(in.AddRequest.ContainerIps[0].Address, "/")[0]
	macAddr := in.MacAddr

	portID, err := getPortID(in.HostIfName)
	if err != nil {
		logger.Errorf("Failed to get port id for %s, err: %v",
			in.HostIfName, err)
		out.Successful = false
		return out, err
	}

	logger.Infof("Interface: %s, port id: %d", in.HostIfName, portID)

	status, err := insertRule(s.log, ctx, server.p4RtC, macAddr,
		ipAddr, int(portID), p4.ENDPOINT)
	out.Successful = status
	return out, err
}

func (s *ApiServer) DeleteNetwork(ctx context.Context, in *proto.DeleteNetworkRequest) (*proto.DelReply, error) {
	var err error

	logger := s.log.WithField("func", "DeleteNetwork")
	logger.Infof("Incoming Del request %s", in.String())

	out := &proto.DelReply{
		Successful: true,
	}

	server := NewApiServer()

	ipAddr := strings.Split(in.Ipv4Addr, "/")[0]
	macAddr := in.MacAddr

	ep := store.EndPoint{
		PodIpAddress: ipAddr,
	}

	entry := ep.GetFromStore()
	if entry == nil {
		err = fmt.Errorf("Entry for %s does not exist in the store", ipAddr)
		out.Successful = false
		return out, err
	}

	if err = p4.DeleteCniRules(ctx, server.p4RtC, macAddr, ipAddr); err != nil {
		logger.Errorf("Failed to delete the entries for %s %s", macAddr, ipAddr)
		out.Successful = false
		return out, err
	}
	logger.Infof("Deleted the entries %s %s from the pipeline", macAddr, ipAddr)

	if ep.DeleteFromStore() != true {
		out.Successful = false
		err = fmt.Errorf("Failed to delete %s %s from the store", macAddr, ipAddr)
		return out, err
	}
	logger.Infof("Deleted the entries %s %s from the store", macAddr, ipAddr)

	return out, err
}

func (s *ApiServer) SetSnatAddress(ctx context.Context, in *proto.SetSnatAddressRequest) (*proto.Reply, error) {
	logger := log.WithField("func", "SetSnatAddress")
	logger.Infof("Incomming SetSnatAddress %+v", in)
	return &proto.Reply{Successful: true}, nil
}

func (s *ApiServer) NatTranslationAdd(ctx context.Context, in *proto.NatTranslation) (*proto.Reply, error) {
	var err error
	var podPortIDs []uint16
	var podIpAddrs []string
	var podMacAddrs []string
	var podMac string
	var groupID uint32

	out := &proto.Reply{
		Successful: true,
	}

	logger := log.WithField("func", "NatTranslationAdd")

	if in == nil || in.Endpoint == nil {
		logger.Errorf("Invalid service request")
		out.Successful = false
		return out, nil
	}

	logger.Infof("Incoming NatTranslationAdd %+v", in)
	logger.Infof("Service ip %v and port %v proto %v", in.Endpoint.Ipv4Addr, in.Endpoint.Port, in.Proto)
	logger.Infof("Endpoints num %v", len(in.Backends))

	/*
		If there are no backend endpoints for the service,
		nothing to program the pipeline. Simply return from
		the function call.
	*/
	if len(in.Backends) == 0 {
		logger.Errorf("No endpoints in the service. No rules inserted")
		return out, nil
	}

	if len(hostInterfaceMac) == 0 {
		logger.Errorf("Host Interface is not yet setup. Cannot program rules for service ip %s",
			in.Endpoint.Ipv4Addr)
		err = fmt.Errorf("Host Interface is not yet setup. Cannot program rules for service ip %s",
			in.Endpoint.Ipv4Addr)
		out.Successful = false
		return out, err
	}
	/*
		Use Host Interface MAC address for service
	*/
	serviceMacAddr := hostInterfaceMac
	serviceIpAddr := in.Endpoint.Ipv4Addr
	servicePort := uint16(in.Endpoint.Port)
	serviceEndPointMap := map[string]store.ServiceEndPoint{}

	server := NewApiServer()

	for i, e := range in.Backends {
		logger.Infof("Endpoint %v:  %v", i, e.DstEp)

		ipAddr := e.DstEp.Ipv4Addr
		ep := store.EndPoint{
			PodIpAddress: ipAddr,
		}

		/* The backends of the kube-api service runs on the
		host network. So, they use the same IP as the host network.
		For such cases, use host management interface to route all
		non pod traffic. As the input request does not provide the
		service name, identify the service using its port 443.
		*/
		if servicePort == 443 {
			podMac = hostInterfaceMac
		} else {
			entry := ep.GetFromStore()
			if entry == nil {
				err = fmt.Errorf("Entry for %s does not exist in the store", ipAddr)
				out.Successful = false
				return out, err
			}
			epEntry := entry.(store.EndPoint)
			podMac = epEntry.PodMacAddress
		}
		podMacAddrs = append(podMacAddrs, podMac)
		podIpAddrs = append(podIpAddrs, ipAddr)
		podPortIDs = append(podPortIDs, uint16(e.DstEp.Port))

		endPoint := store.ServiceEndPoint{
			IpAddress: ipAddr,
			Port:      e.DstEp.Port,
			MemberID:  uint32(i + 1),
		}
		serviceEndPointMap[ipAddr] = endPoint

	}

	if err, groupID = p4.InsertServiceRules(ctx, server.p4RtC, podIpAddrs, podMacAddrs, podPortIDs, serviceIpAddr, serviceMacAddr, servicePort); err != nil {
		logger.Errorf("Failed to insert the service entry %s into the pipeline", serviceIpAddr)
		out.Successful = false
		return out, err
	}

	service := store.Service{
		ClusterIp:       serviceIpAddr,
		ClusterPort:     uint32(servicePort),
		GroupID:         uint32(groupID),
		ServiceEndPoint: serviceEndPointMap,
	}

	if service.WriteToStore() != true {
		logger.Errorf("Failed to insert service entry %s into the store", serviceIpAddr)
		err = fmt.Errorf("Failed to insert service %s into the store", serviceIpAddr)
		out.Successful = false
		return out, err
	}
	logger.Infof("Inserted the service entry %s into the store", serviceIpAddr)

	return out, err
}

func (s *ApiServer) AddDelSnatPrefix(ctx context.Context, in *proto.AddDelSnatPrefixRequest) (*proto.Reply, error) {
	logger := log.WithField("func", "AddDelSnatPrefix")
	logger.Infof("Incomming AddDelSnatPrefix %+v", in)
	return &proto.Reply{Successful: true}, nil
}

func (s *ApiServer) NatTranslationDelete(ctx context.Context, in *proto.NatTranslation) (*proto.Reply, error) {
	logger := log.WithField("func", "NatTranslationDelete")
	logger.Infof("Incomming NatTranslationDelete %+v", in)
	return &proto.Reply{Successful: true}, nil
}

func (s *ApiServer) ActivePolicyUpdate(ctx context.Context, in *proto.ActivePolicyUpdate) (*proto.Reply, error) {
	logger := log.WithField("func", "updatePolicy")
	logger.Infof("Incoming updatePolicy Request %+v", in)
	return &proto.Reply{Successful: true}, nil
}

func (s *ApiServer) ActivePolicyRemove(ctx context.Context, in *proto.ActivePolicyRemove) (*proto.Reply, error) {
	logger := log.WithField("func", "DeletePolicy")
	logger.Infof("Incoming DeletePolicy Request %+v", in)
	return &proto.Reply{Successful: true}, nil
}

func (s *ApiServer) UpdateIPSet(ctx context.Context, in *proto.IPSetUpdate) (*proto.Reply, error) {
	logger := log.WithField("func", "UpdateIPSet")
	logger.Infof("Incoming UpdateIPSet Request %+v", in)
	return &proto.Reply{Successful: true}, nil
}

func (s *ApiServer) UpdateIPSetDelta(ctx context.Context, in *proto.IPSetDeltaUpdate) (*proto.Reply, error) {
	logger := log.WithField("func", "UpdateIPSetDelta")
	logger.Infof("Incoming UpdateIPSetDelta Request %+v", in)
	return &proto.Reply{Successful: true}, nil
}

func (s *ApiServer) RemoveIPSet(ctx context.Context, in *proto.IPSetRemove) (*proto.Reply, error) {
	logger := log.WithField("func", "RemoveIPSet")
	logger.Infof("Incoming RemoveIPSet Request %+v", in)
	return &proto.Reply{Successful: true}, nil
}

func (s *ApiServer) UpdateActiveProfile(ctx context.Context, in *proto.ActiveProfileUpdate) (*proto.Reply, error) {
	logger := log.WithField("func", "UpdateActiveProfile")
	logger.Infof("Incoming UpdateActiveProfile Request %+v", in)
	return &proto.Reply{Successful: true}, nil
}

func (s *ApiServer) RemoveActiveProfile(ctx context.Context, in *proto.ActiveProfileRemove) (*proto.Reply, error) {
	logger := log.WithField("func", "RemoveActiveProfile")
	logger.Infof("Incoming RemoveActiveProfile Request %+v", in)
	return &proto.Reply{Successful: true}, nil
}

func (s *ApiServer) UpdateHostEndpoint(ctx context.Context, in *proto.HostEndpointUpdate) (*proto.Reply, error) {
	logger := log.WithField("func", "UpdateHostEndpoint")
	logger.Infof("Incoming UpdateHostEndpoint Request %+v", in)
	return &proto.Reply{Successful: true}, nil
}

func (s *ApiServer) RemoveHostEndpoint(ctx context.Context, in *proto.HostEndpointRemove) (*proto.Reply, error) {
	logger := log.WithField("func", "RemoveHostEndpoint")
	logger.Infof("Incoming RemoveHostEndpoint Request %+v", in)
	return &proto.Reply{Successful: true}, nil
}

func (s *ApiServer) UpdateLocalEndpoint(ctx context.Context, in *proto.WorkloadEndpointUpdate) (*proto.Reply, error) {
	logger := log.WithField("func", "UpdateLocalEndpoint")
	logger.Infof("Incoming UpdateLocalEndpoint Request %+v", in)
	return &proto.Reply{Successful: true}, nil
}

func (s *ApiServer) RemoveLocalEndpoint(ctx context.Context, in *proto.WorkloadEndpointRemove) (*proto.Reply, error) {
	logger := log.WithField("func", "RemoveLocalEndpoint")
	logger.Infof("Incoming RemoveLocalEndpoint Request %+v", in)
	return &proto.Reply{Successful: true}, nil
}

func (s *ApiServer) UpdateHostMetaData(ctx context.Context, in *proto.HostMetadataUpdate) (*proto.Reply, error) {
	logger := log.WithField("func", "UpdateHostMetaData")
	logger.Infof("Incoming UpdateHostMetaData Request %+v", in)
	return &proto.Reply{Successful: true}, nil
}

func (s *ApiServer) RemoveHostMetaData(ctx context.Context, in *proto.HostMetadataRemove) (*proto.Reply, error) {
	logger := log.WithField("func", "RemoveHostMetaData")
	logger.Infof("Incoming RemoveHostMetaData Request %+v", in)
	return &proto.Reply{Successful: true}, nil
}

func (s *ApiServer) UpdateIPAMPool(ctx context.Context, in *proto.IPAMPoolUpdate) (*proto.Reply, error) {
	logger := log.WithField("func", "UpdateIPAMPool")
	logger.Infof("Incoming UpdateIPAMPool Request %+v", in)
	return &proto.Reply{Successful: true}, nil
}

func (s *ApiServer) RemoveIPAMPool(ctx context.Context, in *proto.IPAMPoolRemove) (*proto.Reply, error) {
	logger := log.WithField("func", "RemoveIPAMPool")
	logger.Infof("Incoming RemoveIPAMPool Request %+v", in)
	return &proto.Reply{Successful: true}, nil
}

func (s *ApiServer) UpdateServiceAccount(ctx context.Context, in *proto.ServiceAccountUpdate) (*proto.Reply, error) {
	logger := log.WithField("func", "UpdateServiceAccount")
	logger.Infof("Incoming UpdateServiceAccount Request %+v", in)
	return &proto.Reply{Successful: true}, nil
}

func (s *ApiServer) RemoveServiceAccount(ctx context.Context, in *proto.ServiceAccountRemove) (*proto.Reply, error) {
	logger := log.WithField("func", "RemoveServiceAccount")
	logger.Infof("Incoming RemoveServiceAccount Request %+v", in)
	return &proto.Reply{Successful: true}, nil
}

func (s *ApiServer) UpdateNamespace(ctx context.Context, in *proto.NamespaceUpdate) (*proto.Reply, error) {
	logger := log.WithField("func", "UpdateNamespace")
	logger.Infof("Incoming UpdateNamespace Request %+v", in)
	return &proto.Reply{Successful: true}, nil
}

func (s *ApiServer) RemoveNamespace(ctx context.Context, in *proto.NamespaceRemove) (*proto.Reply, error) {
	logger := log.WithField("func", "RemoveNamespace")
	logger.Infof("Incoming RemoveNamespace Request %+v", in)
	return &proto.Reply{Successful: true}, nil
}

func (s *ApiServer) UpdateRoute(ctx context.Context, in *proto.RouteUpdate) (*proto.Reply, error) {
	logger := log.WithField("func", "UpdateRoute")
	logger.Infof("Incoming UpdateRoute Request %+v", in)
	return &proto.Reply{Successful: true}, nil
}

func (s *ApiServer) RemoveRoute(ctx context.Context, in *proto.RouteRemove) (*proto.Reply, error) {
	logger := log.WithField("func", "RemoveRoute")
	logger.Infof("Incoming RemoveRoute Request %+v", in)
	return &proto.Reply{Successful: true}, nil
}

func (s *ApiServer) UpdateVXLANTunnelEndpoint(ctx context.Context, in *proto.VXLANTunnelEndpointUpdate) (*proto.Reply, error) {
	logger := log.WithField("func", "UpdateVXLANTunnelEndpoint")
	logger.Infof("Incoming UpdateVXLANTunnelEndpoint Request %+v", in)
	return &proto.Reply{Successful: true}, nil
}

func (s *ApiServer) RemoveVXLANTunnelEndpoint(ctx context.Context, in *proto.VXLANTunnelEndpointRemove) (*proto.Reply, error) {
	logger := log.WithField("func", "RemoveVXLANTunnelEndpoint")
	logger.Infof("Incoming RemoveVXLANTunnelEndpoint Request %+v", in)
	return &proto.Reply{Successful: true}, nil
}

func (s *ApiServer) UpdateWireguardEndpoint(ctx context.Context, in *proto.WireguardEndpointUpdate) (*proto.Reply, error) {
	logger := log.WithField("func", "UpdateWireguardEndpoint")
	logger.Infof("Incoming UpdateWireguardEndpoint Request %+v", in)
	return &proto.Reply{Successful: true}, nil
}

func (s *ApiServer) RemoveWireguardEndpoint(ctx context.Context, in *proto.WireguardEndpointRemove) (*proto.Reply, error) {
	logger := log.WithField("func", "RemoveWireguardEndpoint")
	logger.Infof("Incoming RemoveWireguardEndpoint Request %+v", in)
	return &proto.Reply{Successful: true}, nil
}

func (s *ApiServer) UpdateGlobalBGPConfig(ctx context.Context, in *proto.GlobalBGPConfigUpdate) (*proto.Reply, error) {
	logger := log.WithField("func", "UpdateGlobalBGPConfig")
	logger.Infof("Incoming UpdateGlobalBGPConfig Request %+v", in)
	return &proto.Reply{Successful: true}, nil
}

func (s *ApiServer) SetupHostInterface(ctx context.Context, in *proto.SetupHostInterfaceRequest) (*proto.Reply, error) {
	var err error

	logger := s.log.WithField("func", "SetupHostInterface")
	logger.Infof("Incoming SetupHostInterface request %s", in.String())

	out := &proto.Reply{
		Successful: true,
	}

	server := NewApiServer()

	ipAddr := strings.Split(in.Ipv4Addr, "/")[0]
	macAddr := in.MacAddr
	portID, err := getPortID(in.IfName)
	if err != nil {
		logger.Errorf("Failed to get port id for %s, err: %v",
			in.IfName, err)
		out.Successful = false
		return out, err
	}

	logger.Infof("Interface: %s, port id: %d", in.IfName, portID)

	status, err := insertRule(s.log, ctx, server.p4RtC, macAddr,
		ipAddr, int(portID), p4.HOST)
	out.Successful = status

	hostInterfaceMac = macAddr

	return out, err
}

// Check is used to check the status of GRPC service
func (s *ApiServer) Check(ctx context.Context, in *healthgrpc.HealthCheckRequest) (*healthgrpc.HealthCheckResponse, error) {
	if types.InfraManagerServerStatus != types.ServerStatusOK {
		return &healthgrpc.HealthCheckResponse{Status: healthgrpc.HealthCheckResponse_NOT_SERVING}, errors.New("InfraManager server is not serving")
	}
	return &healthgrpc.HealthCheckResponse{Status: healthgrpc.HealthCheckResponse_SERVING}, nil
}

// Watch was created to fulfil interface requirements, unused
func (s *ApiServer) Watch(in *healthgrpc.HealthCheckRequest, _ healthgrpc.Health_WatchServer) error {
	return errors.New("Unimplemented")
}
