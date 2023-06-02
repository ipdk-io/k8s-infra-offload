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
	"unsafe"

	"github.com/ipdk-io/k8s-infra-offload/pkg/types"
	"github.com/ipdk-io/k8s-infra-offload/pkg/utils"
	"github.com/ipdk-io/k8s-infra-offload/proto"
	"gopkg.in/tomb.v2"

	"github.com/antoninbas/p4runtime-go-client/pkg/client"
	conf "github.com/ipdk-io/k8s-infra-offload/pkg/inframanager/config"
	"github.com/ipdk-io/k8s-infra-offload/pkg/inframanager/p4"
	"github.com/ipdk-io/k8s-infra-offload/pkg/inframanager/store"
	pb "github.com/ipdk-io/k8s-infra-offload/proto"

	p4_v1 "github.com/p4lang/p4runtime/go/p4/v1"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	healthgrpc "google.golang.org/grpc/health/grpc_health_v1"
)

var config *conf.Configuration
var hostInterfaceMac string

func PutConf(c *conf.Configuration) {
	config = c
}

type ProtoIpSetIDX struct {
	ruleMaskId int
	exists     bool
	IpSetIDX   store.IpSetIDX
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

func GetLogLevel() string {
	return config.LogLevel
}

func OpenP4RtC(ctx context.Context, high uint64, low uint64, stopCh <-chan struct{}) error {
	var err error

	log.Infof("Connecting to P4Runtime Server at %s", config.Infrap4dGrpcServer.Addr)

	server := NewApiServer()

	server.p4RtCConn, err = utils.GrpcDial(config.Infrap4dGrpcServer.Addr,
		utils.GetConnType(config.Infrap4dGrpcServer.Conn), utils.Infrap4dGrpcServer)
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

	server.gNMICConn, err = utils.GrpcDial(config.Infrap4dGnmiServer.Addr,
		utils.GetConnType(config.Infrap4dGnmiServer.Conn), utils.Infrap4dGnmiServer)
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
	logger.Infof("Starting infra-manager gRPC server, auth: %s",
		config.InfraManager.Conn)

	managerAddr := fmt.Sprintf("%s:%s", types.InfraManagerAddr, types.InfraManagerPort)
	listen, err := net.Listen(types.ServerNetProto, managerAddr)
	if err != nil {
		logger.Fatalf("failed to listen on %s://%s, err: %v", types.ServerNetProto, managerAddr, err)
	}

	server := NewApiServer()
	server.grpc, err = utils.NewGrpcServer(utils.ServerParams{
		KeepAlive: true,
		ConnType:  utils.GetConnType(config.InfraManager.Conn),
		ConClient: utils.InfraAgent,
	})

	if err != nil {
		logger.Fatalf("Failed to start inframanager grpc server")
	}

	server.listener = listen
	server.log = log

	proto.RegisterInfraAgentServer(server.grpc, server)
	healthgrpc.RegisterHealthServer(server.grpc, server)
	logger.Infof("Infra Manager serving on %s://%s", types.ServerNetProto, managerAddr)
	return server
}

func InsertDefaultRule() {
	server := NewApiServer()

	IP, netIp, err := net.ParseCIDR(types.DefaultRoute)
	if err != nil {
		log.Errorf("Failed to get IP from the default route cidr %s", types.DefaultRoute)
		return
	}

	_ = netIp

	ip := IP.String()
	if len(ip) == 0 {
		log.Errorf("Empty value %s, cannot program default gateway", types.DefaultRoute)
		return
	}

	log.Infof("Inserting default gateway rule for arp-proxy route")
	if err := p4.ArptToPortTable(context.Background(), server.p4RtC, ip,
		types.ArpProxyDefaultPort, true); err != nil {
		log.Errorf("Failed to insert the default rule for arp-proxy")
	}
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

			logger.Debugf("Entry %s %s %d already exists", macAddr, ipAddr, portID)
			return true, nil
		} else {
			err = fmt.Errorf("A different entry for %s, already exists in the store", ipAddr)
			return false, err
		}
	}

	logger.Infof("Inserting entry into the cni tables")
	if err = p4.InsertCniRules(ctx, p4RtC, macAddr, ipAddr, portID, ifaceType); err != nil {
		logger.Errorf("Failed to insert the entries for cni add %s %s", macAddr, ipAddr)
		return false, err
	}
	logger.Debugf("Inserted the entries %s %s %d into the pipeline", macAddr, ipAddr, portID)

	if ep.WriteToStore() != true {
		err = fmt.Errorf("Failed to add %s %s %d entry to the store", macAddr, ipAddr, portID)
		return false, err
	}
	logger.Debugf("Inserted the entries %s %s %d into the store", macAddr, ipAddr, portID)

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
	logger.Debugf("Deleted the entries %s %s from the pipeline", macAddr, ipAddr)

	if ep.DeleteFromStore() != true {
		out.Successful = false
		err = fmt.Errorf("Failed to delete %s %s from the store", macAddr, ipAddr)
		return out, err
	}
	logger.Debugf("Deleted the entries %s %s from the store", macAddr, ipAddr)

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
	var serviceEpIpAddrs []string

	out := &proto.Reply{
		Successful: true,
	}
	update := false

	logger := log.WithField("func", "NatTranslationAdd")

	if in == nil || in.Endpoint == nil {
		logger.Errorf("Invalid NatTranslationAdd request")
		err := fmt.Errorf("Invalid NatTranslationAdd request")
		return out, err
	}

	/*
		If there are no backend endpoints for the service,
		nothing to program the pipeline. Simply return from
		the function call.
	*/
	if len(in.Backends) == 0 {
		logger.Errorf("No endpoints in the service %s:%s:%d. No rules inserted",
			in.Endpoint.Ipv4Addr, in.Proto, in.Endpoint.Port)
		return out, nil
	}

	if len(hostInterfaceMac) == 0 {
		logger.Errorf("Host Interface is not yet setup. Cannot program rules for service %s:%s:%d",
			in.Endpoint.Ipv4Addr, in.Proto, in.Endpoint.Port)
		err = fmt.Errorf("Host Interface is not yet setup. Cannot program rules for service %s:%s:%d",
			in.Endpoint.Ipv4Addr, in.Proto, in.Endpoint.Port)
		out.Successful = false
		return out, err
	}
	/*
		Use Host Interface MAC address for service
	*/
	serviceMacAddr := hostInterfaceMac
	serviceIpAddr := in.Endpoint.Ipv4Addr

	service := store.Service{
		ClusterIp: serviceIpAddr,
		Port:      in.Endpoint.Port,
		Proto:     in.Proto,
	}

	entry := service.GetFromStore()
	/*
		Service already exists in the store.
		Update with new endpoints.
	*/
	if entry != nil {
		logger.Infof("Incoming NatTranslationUpdate %+v", in)
		logger.Debugf("Service ip %v and proto %v port %v , num of endpoints %v",
			in.Endpoint.Ipv4Addr, in.Proto, in.Endpoint.Port, len(in.Backends))

		service = entry.(store.Service)
		if service.Port != in.Endpoint.Port {
			logger.Errorf("Port mismatch for the service %v, old port: %v, new port : %v",
				service.ClusterIp, service.Port, in.Endpoint.Port)
			err = fmt.Errorf("Port mismatch for the service %v, old port: %v, new port : %v",
				service.ClusterIp, service.Port, in.Endpoint.Port)
			out.Successful = false
			return out, err
		}

		for ipAddr := range service.ServiceEndPoint {
			serviceEpIpAddrs = append(serviceEpIpAddrs, ipAddr)
		}

		update = true

	} else {
		/*
			New service. Add it to store
		*/
		logger.Infof("Incoming NatTranslationAdd %+v", in)
		logger.Debugf("Service ip %v proto %v port %v, num of endpoints %v",
			in.Endpoint.Ipv4Addr, in.Proto, in.Endpoint.Port, len(in.Backends))

		service.MacAddr = serviceMacAddr
		service.NumEndPoints = 0
		service.ServiceEndPoint = make(map[string]store.ServiceEndPoint)
	}

	server := NewApiServer()
	newEps := 0

	for _, e := range in.Backends {
		ipAddr := e.DstEp.Ipv4Addr
		if utils.IsIn(ipAddr, serviceEpIpAddrs) {
			continue
		}
		newEps++

		podIpAddrs = append(podIpAddrs, ipAddr)
		podPortIDs = append(podPortIDs, uint16(e.DstEp.Port))

	}

	if newEps == 0 {
		logger.Info("No new endpoints in the service. No rules inserted")
		return out, err
	}

	if err, service = p4.InsertServiceRules(ctx, server.p4RtC, podIpAddrs,
		podPortIDs, service, update); err != nil {
		logger.Errorf("Failed to insert the service entry %s:%s:%d, backends: %v, into the pipeline",
			serviceIpAddr, in.Proto, in.Endpoint.Port, podIpAddrs)
		out.Successful = false
		return out, err
	}
	logger.Debugf("Inserted the service entry %s:%s:%d, backends: %v into the pipeline",
		serviceIpAddr, in.Proto, in.Endpoint.Port, podIpAddrs)

	if update {
		/* Update only the endpoint details to the store */
		if !service.UpdateToStore() {
			logger.Errorf("Failed to update service entry %s:%s:%d, backends: %v, into the store. Reverting from the pipeline",
				serviceIpAddr, in.Proto, in.Endpoint.Port, podIpAddrs)

			p4.DeleteServiceRules(ctx, server.p4RtC, service)

			err = fmt.Errorf("Failed to update service %s:%s:%d, backends: %v into the store",
				serviceIpAddr, in.Proto, in.Endpoint.Port, podIpAddrs)
			out.Successful = false
			return out, err
		}
		logger.Debugf("Updated the service entry %s:%s:%d, backends: %v in the store",
			serviceIpAddr, in.Proto, in.Endpoint.Port, podIpAddrs)
	} else {
		if !service.WriteToStore() {
			logger.Errorf("Failed to insert service entry %s:%s:%d, backends: %v into the store. Reverting from the pipeline",
				serviceIpAddr, in.Proto, in.Endpoint.Port, podIpAddrs)

			p4.DeleteServiceRules(ctx, server.p4RtC, service)

			err = fmt.Errorf("Failed to insert service %s:%s:%d, backends: %v into the store",
				serviceIpAddr, in.Proto, in.Endpoint.Port, podIpAddrs)
			out.Successful = false
			return out, err
		}
		logger.Debugf("Inserted the service entry %s:%s:%d, backends: %v into the store",
			serviceIpAddr, in.Proto, in.Endpoint.Port, podIpAddrs)
	}

	return out, err
}

func (s *ApiServer) AddDelSnatPrefix(ctx context.Context, in *proto.AddDelSnatPrefixRequest) (*proto.Reply, error) {
	logger := log.WithField("func", "AddDelSnatPrefix")
	logger.Infof("Incomming AddDelSnatPrefix %+v", in)
	return &proto.Reply{Successful: true}, nil
}

func (s *ApiServer) NatTranslationDelete(ctx context.Context, in *proto.NatTranslation) (*proto.Reply, error) {
	logger := log.WithField("func", "NatTranslationDelete")
	logger.Infof("Incoming NatTranslationDelete %+v", in)

	out := &proto.Reply{
		Successful: true,
	}
	service := store.Service{
		ClusterIp: in.Endpoint.Ipv4Addr,
		Port:      in.Endpoint.Port,
		Proto:     in.Proto,
	}

	server := NewApiServer()

	if err := p4.DeleteServiceRules(ctx, server.p4RtC, service); err != nil {
		logger.Errorf("Failed to delete the service entry %s:%s:%d from the pipeline",
			in.Endpoint.Ipv4Addr, in.Proto, in.Endpoint.Port)
		out.Successful = false
		return out, err
	}

	if !service.DeleteFromStore() {
		logger.Errorf("Failed to delete service entry %s:%s:%d from the store",
			in.Endpoint.Ipv4Addr, in.Proto, in.Endpoint.Port)

		err := fmt.Errorf("Failed to delete service entry %s:%s:%d from the store",
			in.Endpoint.Ipv4Addr, in.Proto, in.Endpoint.Port)
		out.Successful = false
		return out, err
	}

	return out, nil
}

func (s *ApiServer) ActivePolicyUpdate(ctx context.Context, in *proto.ActivePolicyUpdate) (*proto.Reply, error) {
	var inTcpSet, inUdpSet, outTcpSet, outUdpSet ProtoIpSetIDX
	var tbltype p4.OperationType

	out := &proto.Reply{
		Successful: true,
	}

	logger := log.WithField("func", "updatePolicy")

	if in == nil || unsafe.Sizeof(*in) <= 0 {
		err := errors.New("Empty policy add/update request")
		logger.Errorf("Empty policy add/update request.")
		out.Successful = false
		return out, err
	}

	logger.Infof("Incoming updatePolicy Request %+v", in)

	server := NewApiServer()

	inTcpSet.IpSetIDX.Direction = "RX"
	inUdpSet.IpSetIDX.Direction = "RX"
	outTcpSet.IpSetIDX.Direction = "TX"
	outUdpSet.IpSetIDX.Direction = "TX"

	inTcpSet.IpSetIDX.Protocol = p4.PROTO_TCP
	inUdpSet.IpSetIDX.Protocol = p4.PROTO_UDP
	outTcpSet.IpSetIDX.Protocol = p4.PROTO_TCP
	outUdpSet.IpSetIDX.Protocol = p4.PROTO_UDP

	policy := store.Policy{
		PolicyName: in.Id.Name,
	}

	/*
		Check if the policy exists.
	*/
	entry := policy.GetFromStore()
	if entry != nil {
		storePolicy := entry.(store.Policy)
		logger.Infof("Network policy %s exists. Updating the policy",
			storePolicy.PolicyName)
		tbltype = p4.PolicyUpdate

		/*
			Check the existing policy's ipset indexes.
			If exists, use the same ipset index.
		*/
		for _, ipSetIDX := range storePolicy.IpSetIDXs {
			switch ipSetIDX.Direction {
			case "RX":
				switch ipSetIDX.Protocol {
				case p4.PROTO_UDP:
					inUdpSet.IpSetIDX.Index = ipSetIDX.Index
					inUdpSet.exists = true
				default:
					inTcpSet.IpSetIDX.Index = ipSetIDX.Index
					inTcpSet.exists = true
				}
			case "TX":
				switch ipSetIDX.Protocol {
				case p4.PROTO_UDP:
					outUdpSet.IpSetIDX.Index = ipSetIDX.Index
					outUdpSet.exists = true
				default:
					outTcpSet.IpSetIDX.Index = ipSetIDX.Index
					outTcpSet.exists = true
				}
			}
		}

	} else {
		tbltype = p4.PolicyAdd
		logger.Infof("Adding a new network policy %s.", policy.PolicyName)
	}

	for _, rule := range in.Policy.InboundRules {
		// Currently supporting only cidrs
		if len(rule.SrcNet) == 0 || len(rule.SrcNet[0]) == 0 {
			continue
		}
		r := store.Rule{
			RuleID: rule.RuleId,
			PortRange: []uint16{
				uint16(rule.DstPorts[0].First),
				uint16(rule.DstPorts[0].Last),
			},
			Cidr: rule.SrcNet[0],
		}

		switch rule.Protocol.GetName() {
		case "udp":
			if !inUdpSet.exists {
				inUdpSet.IpSetIDX.Index = uint16(store.GetNewPolicyIpsetIDX())
				inUdpSet.exists = true
			}
			r.RuleMask = p4.GenerateMask(inUdpSet.ruleMaskId)
			inUdpSet.ruleMaskId++
			inUdpSet.IpSetIDX.Rules[rule.RuleId] = r
			inUdpSet.exists = true

			inUdpSet.IpSetIDX.DportRange = append(inUdpSet.IpSetIDX.DportRange,
				uint16(rule.DstPorts[0].First))
			inUdpSet.IpSetIDX.DportRange = append(inUdpSet.IpSetIDX.DportRange,
				uint16(rule.DstPorts[0].Last))
		default:
			if !inTcpSet.exists {
				inTcpSet.IpSetIDX.Index = uint16(store.GetNewPolicyIpsetIDX())
				inTcpSet.exists = true
			}
			r.RuleMask = p4.GenerateMask(inTcpSet.ruleMaskId)
			inTcpSet.ruleMaskId++
			inTcpSet.IpSetIDX.Rules[rule.RuleId] = r
			inTcpSet.exists = true

			inTcpSet.IpSetIDX.DportRange = append(inTcpSet.IpSetIDX.DportRange,
				uint16(rule.DstPorts[0].First))
			inTcpSet.IpSetIDX.DportRange = append(inTcpSet.IpSetIDX.DportRange,
				uint16(rule.DstPorts[0].Last))

		}
	}

	for _, rule := range in.Policy.OutboundRules {
		// Currently supporting only cidrs
		if len(rule.DstNet) == 0 || len(rule.DstNet[0]) == 0 {
			continue
		}
		r := store.Rule{
			RuleID: rule.RuleId,
			PortRange: []uint16{
				uint16(rule.DstPorts[0].First),
				uint16(rule.DstPorts[0].Last),
			},
			Cidr: rule.DstNet[0],
		}

		switch rule.Protocol.GetName() {
		case "udp":
			if !outUdpSet.exists {
				outUdpSet.IpSetIDX.Index = uint16(store.GetNewPolicyIpsetIDX())
				outUdpSet.exists = true
			}
			r.RuleMask = p4.GenerateMask(outUdpSet.ruleMaskId)
			outUdpSet.ruleMaskId++
			outUdpSet.IpSetIDX.Rules[rule.RuleId] = r

			outUdpSet.IpSetIDX.DportRange = append(outUdpSet.IpSetIDX.DportRange,
				uint16(rule.DstPorts[0].First))
			outUdpSet.IpSetIDX.DportRange = append(outUdpSet.IpSetIDX.DportRange,
				uint16(rule.DstPorts[0].Last))
		default:
			if !outTcpSet.exists {
				outTcpSet.IpSetIDX.Index = uint16(store.GetNewPolicyIpsetIDX())
				outTcpSet.exists = true
			}
			r.RuleMask = p4.GenerateMask(outTcpSet.ruleMaskId)
			outTcpSet.ruleMaskId++
			outTcpSet.IpSetIDX.Rules[rule.RuleId] = r

			outTcpSet.IpSetIDX.DportRange = append(outTcpSet.IpSetIDX.DportRange,
				uint16(rule.DstPorts[0].First))
			outTcpSet.IpSetIDX.DportRange = append(outTcpSet.IpSetIDX.DportRange,
				uint16(rule.DstPorts[0].Last))
		}

		if inTcpSet.exists {
			policy.IpSetIDXs[inTcpSet.IpSetIDX.Index] = inTcpSet.IpSetIDX
		}
		if outTcpSet.exists {
			policy.IpSetIDXs[outTcpSet.IpSetIDX.Index] = outTcpSet.IpSetIDX
		}
		if inUdpSet.exists {
			policy.IpSetIDXs[inUdpSet.IpSetIDX.Index] = inUdpSet.IpSetIDX
		}
		if outUdpSet.exists {
			policy.IpSetIDXs[outUdpSet.IpSetIDX.Index] = outUdpSet.IpSetIDX
		}
	}

	err := p4.PolicyTableEntries(ctx, server.p4RtC, tbltype, policy)
	if err != nil {
		logger.Errorf("Failed to add/update policy to the pipeline")
		err := fmt.Errorf("Failed to add/update policy to the pipeline")
		out.Successful = false
		return out, err
	}

	if ok := policy.WriteToStore(); !ok {
		logger.Errorf("Failed to add/update policy to the store")
		err := fmt.Errorf("Failed to add/update policy to the store")
		out.Successful = false
		return out, err
	}

	return out, nil
}

func (s *ApiServer) ActivePolicyRemove(ctx context.Context, in *proto.ActivePolicyRemove) (*proto.Reply, error) {
	logger := log.WithField("func", "DeletePolicy")

	out := &proto.Reply{
		Successful: true,
	}

	if in == nil || unsafe.Sizeof(*in) <= 0 {
		err := errors.New("Empty policy delete request")
		logger.Errorf("Empty policy delete request.")
		out.Successful = false
		return out, err
	}

	logger.Infof("Incoming deletePolicy Request %+v", in)

	server := NewApiServer()

	policy := store.Policy{
		PolicyName: in.Id.Name,
	}

	/*
		Check if the policy exists.
	*/
	entry := policy.GetFromStore()
	if entry == nil {
		logger.Errorf("Policy %s does not exist", in.Id.Name)
		err := fmt.Errorf("Policy %s does not exist", in.Id.Name)
		out.Successful = false
		return out, err
	}

	policy = entry.(store.Policy)

	err := p4.PolicyTableEntries(ctx, server.p4RtC, p4.PolicyDel, policy)
	if err != nil {
		logger.Errorf("Failed to add/update policy to the pipeline")
		err := fmt.Errorf("Failed to add/update policy to the pipeline")
		out.Successful = false
		return out, err
	}

	if ok := policy.DeleteFromStore(); !ok {
		logger.Errorf("Failed to delete policy to the store")
		err := fmt.Errorf("Failed to delete policy to the store")
		out.Successful = false
		return out, err
	}

	return out, nil
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
	var tbltype p4.OperationType

	logger := log.WithField("func", "UpdateLocalEndpoint")

	out := &proto.Reply{
		Successful: true,
	}

	if in == nil || unsafe.Sizeof(*in) <= 0 {
		err := errors.New("Empty update local endpoint request")
		logger.Errorf("Empty update local endpoint request.")
		out.Successful = false
		return out, err
	}

	logger.Infof("Incoming UpdateLocalEndpoint Request %+v", in)

	server := NewApiServer()

	workerEp := store.PolicyWorkerEndPoint{
		WorkerEp:          in.Id.WorkloadId,
		PolicyNameIngress: in.Endpoint.Tiers[0].IngressPolicies,
		PolicyNameEgress:  in.Endpoint.Tiers[0].EgressPolicies,
	}

	entry := workerEp.GetFromStore()
	if entry == nil {
		tbltype = p4.WorkloadAdd
	} else {
		tbltype = p4.WorkloadUpdate
	}

	err := p4.PolicyTableEntries(ctx, server.p4RtC, tbltype, workerEp)
	if err != nil {
		logger.Errorf("Failed to update policies for endpoint %d in the pipeline",
			in.Id.WorkloadId)
		err := fmt.Errorf("Failed to update policies for endpoint %d in the pipeline",
			in.Id.WorkloadId)
		out.Successful = false
		return out, err
	}

	if ok := workerEp.WriteToStore(); !ok {
		logger.Errorf("Failed to update policies for endpoint %d in the store",
			in.Id.WorkloadId)
		err := fmt.Errorf("Failed to update policies for endpoint %d in the store",
			in.Id.WorkloadId)
		out.Successful = false
		return out, err
	}

	return out, nil
}

func (s *ApiServer) RemoveLocalEndpoint(ctx context.Context, in *proto.WorkloadEndpointRemove) (*proto.Reply, error) {
	logger := log.WithField("func", "RemoveLocalEndpoint")

	out := &proto.Reply{
		Successful: true,
	}

	if in == nil || unsafe.Sizeof(*in) <= 0 {
		err := errors.New("Empty remove local endpoint request")
		logger.Errorf("Empty remove local endpoint request.")
		out.Successful = false
		return out, err
	}

	logger.Infof("Incoming RemoveLocalEndpoint Request %+v", in)

	server := NewApiServer()

	workerEp := store.PolicyWorkerEndPoint{
		WorkerEp: in.Id.WorkloadId,
	}
	entry := workerEp.GetFromStore()
	if entry == nil {
		logger.Errorf("Worker endpoint %s does not exist in the store", in.Id.WorkloadId)
		err := fmt.Errorf("Worker endpoint %s does not exist in the store", in.Id.WorkloadId)
		out.Successful = false
		return out, err
	}
	workerEp = entry.(store.PolicyWorkerEndPoint)
	err := p4.PolicyTableEntries(ctx, server.p4RtC, p4.WorkloadDel, workerEp)
	if err != nil {
		logger.Errorf("Failed to delete policies for endpoint %d from the pipeline",
			in.Id.WorkloadId)
		err := fmt.Errorf("Failed delete policies for endpoint %d from the pipeline",
			in.Id.WorkloadId)
		out.Successful = false
		return out, err
	}

	if ok := workerEp.WriteToStore(); !ok {
		logger.Errorf("Failed to delete policies for endpoint %d from the store",
			in.Id.WorkloadId)
		err := fmt.Errorf("Failed to delete policies for endpoint %d from the store",
			in.Id.WorkloadId)
		out.Successful = false
		return out, err
	}

	return out, nil

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

	logger.Debugf("Interface: %s, port id: %d", in.IfName, portID)

	if status, err := insertRule(s.log, ctx, server.p4RtC, macAddr,
		ipAddr, int(portID), p4.HOST); err != nil {
		logger.Errorf("Failed to insert rule to the pipeline ip: %s mac: %s port id: %d err: %v",
			ipAddr, macAddr, portID, err)
		out.Successful = status
		return out, err
	}
	hostInterfaceMac = macAddr

	if len(config.NodeIP) == 0 {
		logger.Errorf("No node ip address configured")
		err = fmt.Errorf("No node ip address configured")
		out.Successful = false
		return out, err
	}

	status, err := insertRule(s.log, ctx, server.p4RtC, hostInterfaceMac,
		config.NodeIP, int(portID), p4.HOST)
	if err != nil {
		logger.Errorf("Failed to insert rule to the pipeline p: %s mac: %s port id: %d err: %v",
			config.NodeIP, macAddr, portID, err)
	}
	out.Successful = status

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
