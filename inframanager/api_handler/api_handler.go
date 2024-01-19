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
	"reflect"
	"strings"
	"sync"
	"time"

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

var hostInterface store.Iface

// To identify different tcp packets based on tcp flag
// ACK RST SYN FIN
var flags = [][]byte{{0x00, 0x00, 0x01, 0x00},
	{0x00, 0x00, 0x00, 0x01},
	{0x00, 0x00, 0x01, 0x01},
	{0x00, 0x01, 0x00, 0x01},
	{0x00, 0x01, 0x01, 0x01},
	{0x01, 0x00, 0x00, 0x01},
	{0x01, 0x00, 0x01, 0x01},
	{0x01, 0x01, 0x00, 0x01},
	{0x01, 0x01, 0x01, 0x01},
	{0x00, 0x01, 0x00, 0x00},
	{0x00, 0x01, 0x01, 0x00},
	{0x01, 0x01, 0x00, 0x00},
	{0x01, 0x01, 0x01, 0x00},
	{0x01, 0x00, 0x00, 0x00},
	{0x01, 0x00, 0x01, 0x00},
	{0x00, 0x00, 0x00, 0x00}}

type Protocol int

const (
	noproto Protocol = iota
	tcp
	udp
)

func SetHostInterface() {
	hostInterface = store.GetHostInterface()
}

type RuleGroupIDX struct {
	ruleMaskId int
	exists     bool
	RuleGroup  store.RuleGroup
}

type ApiServer struct {
	listener   net.Listener
	grpc       *grpc.Server
	config     *conf.Configuration
	log        *log.Entry
	p4RtC      *client.Client
	p4RtCConn  *grpc.ClientConn
	gNMICConn  *grpc.ClientConn
	gNMIClient pb.GNMIClient
}

var api *ApiServer
var once sync.Once
var mutex = &sync.Mutex{}
var replay bool
var replayMutex sync.Mutex
var Infrap4d = utils.NewServerStatus()

func NewApiServer() *ApiServer {
	once.Do(func() {
		api = &ApiServer{}
	})
	return api
}

func GetLogLevel() string {
	return api.config.LogLevel
}

func OpenP4RtC(ctx context.Context, high uint64, low uint64, stopCh <-chan struct{}, config conf.Configuration) error {
	var err error

	server := NewApiServer()

	log.Infof("Connecting to P4Runtime Server at %s", config.Infrap4dGrpcServer.Addr)

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

	//// Set infrap4d to running state
	//Infrap4d.SetRunning()

	low = utils.MakeTimestampMilli()

	electionID := p4_v1.Uint128{High: high, Low: low}
	server.p4RtC = client.NewClient(c, config.DeviceId, &electionID)
	log.Infof("Device id is: %v", config.DeviceId)

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

func OpenGNMICCon(config conf.Configuration) error {
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

func getPortID(ifName string, macAddr net.HardwareAddr) (portID uint32, err error) {

	server := NewApiServer()

	//TODO: Test for SRIOV
	switch server.config.InterfaceType {
	case types.SriovPodInterface, types.CDQInterface:
		portID = (uint32(macAddr[1]) + 16)
		return
	case types.TapInterface:
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

		if resp, err = server.gNMIClient.Get(context.Background(),
			req); err != nil {
			return
		}

		val := (resp.Notification[0].Update[0].Val.Value).(*pb.TypedValue_UintVal)
		portID = (uint32)(val.UintVal)
		return
	default:
		return
	}
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

func CreateServer(conf *conf.Configuration, log *log.Entry) *ApiServer {
	logger := log.WithField("func", "CreateAndStartServer")
	logger.Infof("Starting infra-manager gRPC server, auth: %s",
		conf.InfraManager.Conn)

	managerAddr := fmt.Sprintf("%s:%s", types.InfraManagerAddr, types.InfraManagerPort)
	listen, err := net.Listen(types.ServerNetProto, managerAddr)
	if err != nil {
		logger.Fatalf("failed to listen on %s://%s, err: %v", types.ServerNetProto, managerAddr, err)
	}

	server := NewApiServer()
	server.grpc, err = utils.NewGrpcServer(utils.ServerParams{
		KeepAlive: true,
		ConnType:  utils.GetConnType(conf.InfraManager.Conn),
		ConClient: utils.InfraAgent,
	})

	if err != nil {
		logger.Fatalf("Failed to start inframanager grpc server, err: %v", err)
	}

	server.listener = listen
	server.log = log
	server.config = conf

	proto.RegisterInfraAgentServer(server.grpc, server)
	healthgrpc.RegisterHealthServer(server.grpc, server)
	logger.Infof("Infra Manager serving on %s://%s", types.ServerNetProto, managerAddr)
	return server
}

func recoverPanic(log *log.Entry) {
	if r := recover(); r != nil {
		log.Errorf("Panic occured, %v", r)
		store.SyncDB()
	}
}

func InsertDefaultRule() {
	var portID uint32
	var err error

	/*
		If the default rule is already set, no need to program it again.
	*/
	if store.IsDefaultRuleSet() {
		return
	}

	server := NewApiServer()

	if !ReplaySet() || !Infrap4d.Running() {
		log.Infof("Infrap4d is not running, waiting to restart")
		// Wait till timeout for the infrap4d to restart
		ret := Infrap4d.WaitToRestart(server.config.Infrap4dTimeout)
		if ret == false {
			log.Errorf("Infrap4d is not running while inserting the default rule.")
			return
		}
		log.Infof("Infrap4d is running now")
	}

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

	macAddress, err := net.ParseMAC(server.config.InfraManager.ArpMac)
	if err != nil {
		log.Errorf("Invalid MAC Address: %s, err: %v", server.config.InfraManager.ArpMac, err)
		return
	}

	if server.config.InterfaceType == types.TapInterface {
		portID = types.ArpProxyDefaultPort
	} else {
		if portID, err = getPortID("dummy", macAddress); err != nil {
			log.Errorf("Failed to get port id for %s, err: %v",
				"dummy", err)
			return
		}
	}

	log.Infof("Inserting default gateway rule for arp-proxy route, arp mac: %s", server.config.InfraManager.ArpMac)

	if err := p4.ArptToPortTable(context.Background(), server.p4RtC, ip,
		portID, true); err != nil {
		log.Errorf("Failed to insert the default rule for arp-proxy, err: %v", err)
	}
	//service default rule
	ep := store.EndPoint{
		PodIpAddress:  ip,
		InterfaceID:   portID,
		PodMacAddress: server.config.InfraManager.ArpMac,
	}

	entry := ep.GetFromStore()
	if entry != nil {
		log.Debugf("Entry %s %s %d already exists", macAddress, types.DefaultRoute, portID)
	} else {
		if ep.WriteToStore() != true {
			log.Errorf("Failed to add mac: %s ip: %s port: %d  entry to the store",
				macAddress, types.DefaultRoute, portID)
		}
	}

	action := p4.Insert
	if server.config.InterfaceType != types.TapInterface {
		log.Infof("Inserting default gateway rule for service: ServiceFlowPacketOptions")
		err = p4.ServiceFlowPacketOptions(context.Background(), server.p4RtC, flags, action)
		if err != nil {
			log.Errorf("Failed to insert ServiceFlowPacketOptions")
			return
		}
	}

	store.SetDefaultRule()
	return
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

func insertRule(log *log.Entry, ctx context.Context, p4RtC *client.Client, macAddr string, ipAddr string, portID uint32, ifaceType p4.InterfaceType) (bool, error) {
	var err error

	server := NewApiServer()

	logger := log.WithField("func", "insertRule")

	if ReplaySet() || !Infrap4d.Running() {
		log.Infof("Infrap4d is not running, waiting to restart")
		// Wait till timeout for the infrap4d to restart
		ret := Infrap4d.WaitToRestart(server.config.Infrap4dTimeout)
		if ret == false {
			logger.Errorf("Infrap4d is not running")
			return false, errors.New("Infrap4d is not running")
		}
		log.Infof("Infrap4d is running now")
	}

	ep := store.EndPoint{
		PodIpAddress:  ipAddr,
		InterfaceID:   portID,
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
	ep, err = p4.InsertCniRules(ctx, p4RtC, ep, ifaceType)
	if err != nil {
		logger.Errorf("Failed to insert the entries for cni add %s %s", macAddr, ipAddr)
		return false, err
	}

	logger.Debugf("Inserted the entries mac: %s ip: %s port: %d mod ptr: %d into the pipeline",
		macAddr, ipAddr, portID, ep.ModPtr)

	if ep.WriteToStore() != true {
		err = fmt.Errorf("Failed to add mac: %s ip: %s port: %d mod ptr: %d entry to the store",
			macAddr, ipAddr, portID, ep.ModPtr)
		return false, err
	}

	logger.Debugf("Inserted the entries mac: %s ip: %s port: %d modptr: %d into the store",
		macAddr, ipAddr, portID, ep.ModPtr)

	return true, err
}

func ReplaySet() bool {
	return replay
}

func SetReplay() {
	replayMutex.Lock()
	replay = true
	replayMutex.Unlock()
}
func ClearReplay() {
	replayMutex.Lock()
	replay = false
	replayMutex.Unlock()
}

/*
Read from the store and reprogram all rules to the pipeline.
This is used when the infrap4d is restarted.
*/

func ReplayRules() {
	ctx := context.Background()

	server := NewApiServer()
	defer ClearReplay()

	defaultRouteIP := strings.Split(types.DefaultRoute, "/")[0]
	hostIfaceIP := strings.Split(types.HostInterfaceAddr, "/")[0]
	nodeIP := server.config.NodeIP

	// Program cni add rules for all eps
	eps := store.GetAllEndpoints()
	for _, ep := range eps {
		switch ep.PodIpAddress {
		// Default rule
		case defaultRouteIP:
			var portID uint32
			if server.config.InterfaceType == types.TapInterface {
				portID = types.ArpProxyDefaultPort
			} else {
				macAddr, err := net.ParseMAC(ep.PodMacAddress)
				if err != nil {
					log.Fatalf("Invalid MAC Address: %s, err: %v", server.config.InfraManager.ArpMac, err)
				}
				if portID, err = getPortID("dummy", macAddr); err != nil {
					log.Fatalf("Failed to get port id for %s, err: %v",
						"dummy", err)
				}
			}
			p4.ArptToPortTable(context.Background(),
				server.p4RtC, ep.PodIpAddress, portID, true)

		// SetupHostInterface
		case hostIfaceIP, nodeIP:
			p4.InsertCniRules(ctx, server.p4RtC, ep, p4.HOST)
		// CNI Add
		default:
			p4.InsertCniRules(ctx, server.p4RtC, ep, p4.ENDPOINT)
		}
	}

	// Program service rules
	svcs := store.GetAllServices()
	for _, svc := range svcs {
		var podPortIDs []uint16
		var podIpAddrs []string

		for _, ep := range svc.ServiceEndPoint {
			podIpAddrs = append(podIpAddrs, ep.IpAddress)
			podPortIDs = append(podPortIDs, ep.Port)
		}
		p4.InsertServiceRules(ctx, server.p4RtC, podIpAddrs,
			podPortIDs, svc, false, true)
	}
}

func (s *ApiServer) CreateNetwork(ctx context.Context, in *proto.CreateNetworkRequest) (*proto.AddReply, error) {
	var err error

	logger := s.log.WithField("func", "CreateNetwork")

	defer recoverPanic(logger)

	out := &proto.AddReply{
		Successful: true,
	}

	if in == nil || reflect.DeepEqual(*in, proto.CreateNetworkRequest{}) {
		out.Successful = false
		logger.Errorf("Empty CNI Add request")
		return out, errors.New("Empty CNI Add request")
	}

	if in.AddRequest == nil || reflect.DeepEqual(*in.AddRequest, proto.AddRequest{}) {
		out.Successful = false
		logger.Errorf("Incomplete CNI Add request")
		return out, errors.New("Incomplete CNI Add request")
	}

	if len(in.AddRequest.ContainerIps) == 0 {
		out.Successful = false
		logger.Errorf("Container ip address not provided")
		return out, errors.New("Container ip address not provided")
	}

	logger.Infof("Incoming Add request %s", in.String())

	server := NewApiServer()

	if ReplaySet() || !Infrap4d.Running() {
		log.Infof("Infrap4d is not running, waiting to restart")
		// TODO: Wait till context timeout instead of infrap4d timeout
		// Wait till timeout for the infrap4d to restart
		ret := Infrap4d.WaitToRestart(server.config.Infrap4dTimeout)
		if ret == false {
			out.Successful = false
			return out, errors.New("Infrap4d is not running")
		}
		log.Infof("Infrap4d is running now")
	}

	ipAddr := strings.Split(in.AddRequest.ContainerIps[0].Address, "/")[0]

	if net.ParseIP(ipAddr) == nil {
		out.Successful = false
		logger.Errorf("Invalid container ip address %s", ipAddr)
		return out, fmt.Errorf("Invalid container ip address %s", ipAddr)
	}

	macAddr := in.MacAddr
	macAddress, err := net.ParseMAC(in.MacAddr)
	if err != nil {
		logger.Errorf("Invalid MAC Address %s, err: %v", in.MacAddr, err)
		out.Successful = false
		return out, err
	}

	portID, err := getPortID(in.HostIfName, macAddress)
	if err != nil {
		logger.Errorf("Failed to get port id for %s, err: %v",
			in.HostIfName, err)
		out.Successful = false
		return out, err
	}

	logger.Infof("Interface: %s, port id: %d", in.HostIfName, portID)

	status, err := insertRule(s.log, ctx, server.p4RtC, macAddr,
		ipAddr, portID, p4.ENDPOINT)
	out.Successful = status
	if status {
		out.HostInterfaceName = in.AddRequest.DesiredHostInterfaceName
	}

	return out, err
}

func (s *ApiServer) DeleteNetwork(ctx context.Context, in *proto.DeleteNetworkRequest) (*proto.DelReply, error) {
	var err error

	logger := s.log.WithField("func", "DeleteNetwork")

	defer recoverPanic(logger)

	out := &proto.DelReply{
		Successful: true,
	}

	if in == nil || reflect.DeepEqual(*in, proto.DeleteNetworkRequest{}) {
		out.Successful = false
		logger.Errorf("Empty CNI Del request")
		return out, errors.New("Empty CNI Del request")
	}

	logger.Infof("Incoming Del request %s", in.String())

	server := NewApiServer()

	if ReplaySet() || !Infrap4d.Running() {
		log.Infof("Infrap4d is not running, waiting to restart")
		// Wait till timeout for the infrap4d to restart
		ret := Infrap4d.WaitToRestart(server.config.Infrap4dTimeout)
		if ret == false {
			out.Successful = false
			return out, errors.New("Infrap4d is not running")
		}
		log.Infof("Infrap4d is running now")
	}

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
	epEntry := entry.(store.EndPoint)

	if err = p4.DeleteCniRules(ctx, server.p4RtC, epEntry); err != nil {
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

	defer recoverPanic(logger)

	if in == nil || reflect.DeepEqual(*in, proto.NatTranslation{}) {
		out.Successful = false
		logger.Errorf("Empty NatTranslationAdd request")
		return out, errors.New("Empty NatTranslationAdd request")
	}

	logger.Infof("Incoming NatTranslationAdd request %s", in.String())

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

	if len(hostInterface.Mac) == 0 {
		logger.Errorf("Host Interface is not yet setup. Cannot program rules for service %s:%s:%d",
			in.Endpoint.Ipv4Addr, in.Proto, in.Endpoint.Port)
		err = fmt.Errorf("Host Interface is not yet setup. Cannot program rules for service %s:%s:%d",
			in.Endpoint.Ipv4Addr, in.Proto, in.Endpoint.Port)
		out.Successful = false
		return out, err
	}

	server := NewApiServer()

	if ReplaySet() || !Infrap4d.Running() {
		log.Infof("Infrap4d is not running, waiting to restart")
		// Wait till timeout for the infrap4d to restart
		ret := Infrap4d.WaitToRestart(server.config.Infrap4dTimeout)
		if ret == false {
			out.Successful = false
			return out, errors.New("Infrap4d is not running")
		}
		log.Infof("Infrap4d is running now")
	}

	// Use Host Interface MAC address for service
	serviceMacAddr := hostInterface.Mac
	serviceIpAddr := in.Endpoint.Ipv4Addr

	service := store.Service{
		ClusterIp: serviceIpAddr,
		Port:      uint16(in.Endpoint.Port),
		Proto:     in.Proto,
	}

	entry := service.GetFromStore()

	//	Service already exists in the store.
	//	Update with new endpoints.

	if entry != nil {
		logger.Infof("Incoming NatTranslationUpdate %+v", in)
		logger.Debugf("Service ip %v and proto %v port %v , num of endpoints %v",
			in.Endpoint.Ipv4Addr, in.Proto, in.Endpoint.Port, len(in.Backends))

		service = entry.(store.Service)
		if service.Port != uint16(in.Endpoint.Port) {
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
		//
		//	New service. Add it to store
		//
		logger.Infof("Incoming NatTranslationAdd %+v", in)
		logger.Debugf("Service ip %v proto %v port %v, num of endpoints %v",
			in.Endpoint.Ipv4Addr, in.Proto, in.Endpoint.Port, len(in.Backends))

		service.MacAddr = serviceMacAddr
		service.NumEndPoints = 0
		service.ServiceEndPoint = make(map[string]store.ServiceEndPoint)
	}

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

	//Update: We need to handle in p4 layer.
	err, service = p4.InsertServiceRules(ctx, server.p4RtC, podIpAddrs,
		podPortIDs, service, update, false)
	if err != nil {
		logger.Errorf("Failed to insert the service entry %s:%s:%d, backends: %v, into the pipeline",
			serviceIpAddr, in.Proto, in.Endpoint.Port, podIpAddrs)
		out.Successful = false
		return out, err
	}
	logger.Debugf("Inserted the service entry %s:%s:%d, backends: %v into the pipeline",
		serviceIpAddr, in.Proto, in.Endpoint.Port, podIpAddrs) //Debug

	if update {
		// Update only the endpoint details to the store
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

	out := &proto.Reply{
		Successful: true,
	}

	defer recoverPanic(logger)

	if in == nil || reflect.DeepEqual(*in, proto.NatTranslation{}) {
		out.Successful = false
		logger.Errorf("Empty NatTranslationDelete request")
		return out, errors.New("Empty NatTranslationDelete request")
	}

	logger.Infof("Incoming NatTranslationDelete %+v", in)

	service := store.Service{
		ClusterIp: in.Endpoint.Ipv4Addr,
		Port:      uint16(in.Endpoint.Port),
		Proto:     in.Proto,
	}

	server := NewApiServer()

	if ReplaySet() || !Infrap4d.Running() {
		log.Infof("Infrap4d is not running, waiting to restart")
		// Wait till timeout for the infrap4d to restart
		ret := Infrap4d.WaitToRestart(server.config.Infrap4dTimeout)
		if ret == false {
			out.Successful = false
			return out, errors.New("Infrap4d is not running")
		}
		log.Infof("Infrap4d is running now")
	}

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
	var ingress, egress [3]RuleGroupIDX

	out := &proto.Reply{
		Successful: true,
	}

	logger := log.WithField("func", "updatePolicy")

	defer recoverPanic(logger)

	if in == nil || reflect.DeepEqual(*in, proto.ActivePolicyUpdate{}) {
		err := errors.New("Empty policy add/update request")
		logger.Errorf("Empty policy add/update request.")
		out.Successful = false
		return out, err
	}

	logger.Infof("Incoming updatePolicy Request %+v", in)

	server := NewApiServer()

	/*
		Currently supporting policies for dpdk target only
	*/

	if server.config.InterfaceType != "tap" {
		return out, nil
	}

	if ReplaySet() || !Infrap4d.Running() {
		log.Infof("Infrap4d is not running, waiting to restart")
		// Wait till timeout for the infrap4d to restart
		ret := Infrap4d.WaitToRestart(server.config.Infrap4dTimeout)
		if ret == false {
			out.Successful = false
			return out, errors.New("Infrap4d is not running")
		}
		log.Infof("Infrap4d is running now")
	}

	ingress[tcp].RuleGroup.Protocol = p4.PROTO_TCP
	egress[tcp].RuleGroup.Protocol = p4.PROTO_TCP
	ingress[udp].RuleGroup.Protocol = p4.PROTO_UDP
	egress[udp].RuleGroup.Protocol = p4.PROTO_UDP

	for i := 0; i < 3; i++ {
		ingress[i].RuleGroup.Rules = map[string]store.Rule{}
		egress[i].RuleGroup.Rules = map[string]store.Rule{}
		ingress[i].RuleGroup.Direction = "RX"
		egress[i].RuleGroup.Direction = "TX"
	}

	policy := store.Policy{
		Name: in.Id.Name,
	}

	policy.RuleGroups = map[uint16]store.RuleGroup{}

	for _, rule := range in.Policy.InboundRules {
		// Currently supporting only cidrs
		if len(rule.SrcNet) == 0 || len(rule.SrcNet[0]) == 0 {
			continue
		}

		switch rule.Protocol.GetName() {
		case "udp":
			if !ingress[udp].exists {
				ingress[udp].RuleGroup.Index = uint16(store.GetNewRuleGroupId())
				ingress[udp].exists = true
			}
			r := store.Rule{
				Id: rule.RuleId,
				PortRange: []uint16{
					uint16(rule.DstPorts[0].First),
					uint16(rule.DstPorts[0].Last),
				},
				RuleMask: p4.GenerateMask(ingress[udp].ruleMaskId),
				Cidr:     rule.SrcNet[0],
			}

			ingress[udp].ruleMaskId++
			ingress[udp].RuleGroup.Rules[rule.RuleId] = r
			ingress[udp].exists = true

			ingress[udp].RuleGroup.DportRange = append(ingress[udp].RuleGroup.DportRange,
				uint16(rule.DstPorts[0].First))
			ingress[udp].RuleGroup.DportRange = append(ingress[udp].RuleGroup.DportRange,
				uint16(rule.DstPorts[0].Last))
		case "tcp":
			if !ingress[tcp].exists {
				ingress[tcp].RuleGroup.Index = uint16(store.GetNewRuleGroupId())
				ingress[tcp].exists = true
			}
			r := store.Rule{
				Id: rule.RuleId,
				PortRange: []uint16{
					uint16(rule.DstPorts[0].First),
					uint16(rule.DstPorts[0].Last),
				},
				RuleMask: p4.GenerateMask(ingress[tcp].ruleMaskId),
				Cidr:     rule.SrcNet[0],
			}
			ingress[tcp].ruleMaskId++
			ingress[tcp].RuleGroup.Rules[rule.RuleId] = r
			ingress[tcp].exists = true

			ingress[tcp].RuleGroup.DportRange = append(ingress[tcp].RuleGroup.DportRange,
				uint16(rule.DstPorts[0].First))
			ingress[tcp].RuleGroup.DportRange = append(ingress[tcp].RuleGroup.DportRange,
				uint16(rule.DstPorts[0].Last))
		default:
			if !ingress[noproto].exists {
				ingress[noproto].RuleGroup.Index = uint16(store.GetNewRuleGroupId())
				ingress[noproto].exists = true
			}
			r := store.Rule{
				Id:       rule.RuleId,
				RuleMask: p4.GenerateMask(ingress[noproto].ruleMaskId),
				Cidr:     rule.SrcNet[0],
			}
			ingress[noproto].ruleMaskId++
			ingress[noproto].RuleGroup.Rules[rule.RuleId] = r
			ingress[noproto].exists = true
		}
	}

	for _, rule := range in.Policy.OutboundRules {
		// Currently supporting only cidrs
		if len(rule.DstNet) == 0 || len(rule.DstNet[0]) == 0 {
			continue
		}

		switch rule.Protocol.GetName() {
		case "udp":
			if !egress[udp].exists {
				egress[udp].RuleGroup.Index = uint16(store.GetNewRuleGroupId())
				egress[udp].exists = true
			}
			r := store.Rule{
				Id: rule.RuleId,
				PortRange: []uint16{
					uint16(rule.DstPorts[0].First),
					uint16(rule.DstPorts[0].Last),
				},
				RuleMask: p4.GenerateMask(egress[udp].ruleMaskId),
				Cidr:     rule.DstNet[0],
			}

			egress[udp].ruleMaskId++
			egress[udp].RuleGroup.Rules[rule.RuleId] = r
			egress[udp].exists = true

			egress[udp].RuleGroup.DportRange = append(egress[udp].RuleGroup.DportRange,
				uint16(rule.DstPorts[0].First))
			egress[udp].RuleGroup.DportRange = append(egress[udp].RuleGroup.DportRange,
				uint16(rule.DstPorts[0].Last))
		case "tcp":
			if !egress[tcp].exists {
				egress[tcp].RuleGroup.Index = uint16(store.GetNewRuleGroupId())
				egress[tcp].exists = true
			}
			r := store.Rule{
				Id: rule.RuleId,
				PortRange: []uint16{
					uint16(rule.DstPorts[0].First),
					uint16(rule.DstPorts[0].Last),
				},
				RuleMask: p4.GenerateMask(egress[tcp].ruleMaskId),
				Cidr:     rule.DstNet[0],
			}
			egress[tcp].ruleMaskId++
			egress[tcp].RuleGroup.Rules[rule.RuleId] = r
			egress[tcp].exists = true

			egress[tcp].RuleGroup.DportRange = append(egress[tcp].RuleGroup.DportRange,
				uint16(rule.DstPorts[0].First))
			egress[tcp].RuleGroup.DportRange = append(egress[tcp].RuleGroup.DportRange,
				uint16(rule.DstPorts[0].Last))
		default:
			if !egress[noproto].exists {
				egress[noproto].RuleGroup.Index = uint16(store.GetNewRuleGroupId())
				egress[noproto].exists = true
			}
			r := store.Rule{
				Id:       rule.RuleId,
				RuleMask: p4.GenerateMask(egress[noproto].ruleMaskId),
				Cidr:     rule.DstNet[0],
			}
			egress[noproto].ruleMaskId++
			egress[noproto].RuleGroup.Rules[rule.RuleId] = r
			egress[noproto].exists = true
		}

	}
	for i := 0; i < 3; i++ {
		if ingress[i].exists {
			policy.RuleGroups[ingress[i].RuleGroup.Index] = ingress[i].RuleGroup
		}
		if egress[i].exists {
			policy.RuleGroups[egress[i].RuleGroup.Index] = egress[i].RuleGroup
		}
	}

	err := p4.PolicyTableEntries(ctx, server.p4RtC, p4.PolicyAdd, policy)
	if err != nil {
		logger.Errorf("Failed to add/update policy to the pipeline")
		err := fmt.Errorf("Failed to add/update policy to the pipeline")
		out.Successful = false
		return out, err
	}
	logger.Infof("Successfully added/updated policy %v to the pipeline", policy)

	if ok := policy.UpdateToStore(); !ok {
		logger.Errorf("Failed to add/update policy to the store")
		err := fmt.Errorf("Failed to add/update policy to the store")
		out.Successful = false
		return out, err
	}
	logger.Infof("Successfully added/updated policy %v to the store", policy)

	return out, nil
}

func (s *ApiServer) ActivePolicyRemove(ctx context.Context, in *proto.ActivePolicyRemove) (*proto.Reply, error) {
	logger := log.WithField("func", "DeletePolicy")

	out := &proto.Reply{
		Successful: true,
	}

	defer recoverPanic(logger)

	server := NewApiServer()

	/*
		Currently supporting policies for dpdk target only
	*/

	if server.config.InterfaceType != "tap" {
		return out, nil
	}

	if in == nil || reflect.DeepEqual(*in, proto.ActivePolicyRemove{}) {
		err := errors.New("Empty policy delete request")
		logger.Errorf("Empty policy delete request.")
		out.Successful = false
		return out, err
	}

	logger.Infof("Incoming deletePolicy Request %+v", in)

	if ReplaySet() || !Infrap4d.Running() {
		log.Infof("Infrap4d is not running, waiting to restart")
		// Wait till timeout for the infrap4d to restart
		ret := Infrap4d.WaitToRestart(server.config.Infrap4dTimeout)
		if ret == false {
			out.Successful = false
			return out, errors.New("Infrap4d is not running")
		}
		log.Infof("Infrap4d is running now")
	}

	policy := store.Policy{
		Name: in.Id.Name,
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

	logger.Infof("Successfully deleted policy %v to the store", policy)

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
	logger := log.WithField("func", "UpdateLocalEndpoint")

	defer recoverPanic(logger)

	out := &proto.Reply{
		Successful: true,
	}

	server := NewApiServer()

	/*
		Currently supporting policies for dpdk target only
	*/

	if server.config.InterfaceType != "tap" {
		return out, nil
	}

	if in == nil || reflect.DeepEqual(*in, proto.WorkloadEndpointUpdate{}) {
		err := errors.New("Empty update local endpoint request")
		logger.Errorf("Empty update local endpoint request.")
		out.Successful = false
		return out, err
	}

	logger.Infof("Incoming UpdateLocalEndpoint Request %+v", in)

	if len(in.Endpoint.Ipv4Nets) == 0 {
		err := errors.New("No IP address assigned for the endpoint")
		logger.Errorf("No IP addresses assigned for the endpoint")
		out.Successful = false
		return out, err
	}

	if ReplaySet() || !Infrap4d.Running() {
		log.Infof("Infrap4d is not running, waiting to restart")
		// Wait till timeout for the infrap4d to restart
		ret := Infrap4d.WaitToRestart(server.config.Infrap4dTimeout)
		if ret == false {
			out.Successful = false
			return out, errors.New("Infrap4d is not running")
		}
		log.Infof("Infrap4d is running now")
	}

	ipAddr := strings.Split(in.Endpoint.Ipv4Nets[0], "/")[0]
	if net.ParseIP(ipAddr) == nil {
		err := fmt.Errorf("Invalid IP addr : %s", ipAddr)
		logger.Errorf("Invalid IP Addr: %s", ipAddr)
		out.Successful = false
		return out, err
	}

	workerEp := store.PolicyWorkerEndPoint{
		WorkerEp: in.Id.WorkloadId,
		WorkerIp: ipAddr,
	}

	if len(in.Endpoint.Tiers) > 0 {
		if len(in.Endpoint.Tiers[0].IngressPolicies) > 0 {
			workerEp.PolicyNameIngress = in.Endpoint.Tiers[0].IngressPolicies
		}
		if len(in.Endpoint.Tiers[0].EgressPolicies) > 0 {
			workerEp.PolicyNameEgress = in.Endpoint.Tiers[0].EgressPolicies
		}
	}

	err := p4.PolicyTableEntries(ctx, server.p4RtC, p4.WorkloadAdd, workerEp)
	if err != nil {
		logger.Errorf("Failed to update policies for endpoint %s in the pipeline",
			in.Id.WorkloadId)
		err := fmt.Errorf("Failed to update policies for endpoint %s in the pipeline",
			in.Id.WorkloadId)
		out.Successful = false
		return out, err
	}

	if ok := workerEp.UpdateToStore(); !ok {
		logger.Errorf("Failed to update policies for endpoint %s in the store",
			in.Id.WorkloadId)
		err := fmt.Errorf("Failed to update policies for endpoint %s in the store",
			in.Id.WorkloadId)
		out.Successful = false
		return out, err
	}

	return out, nil
}

func (s *ApiServer) RemoveLocalEndpoint(ctx context.Context, in *proto.WorkloadEndpointRemove) (*proto.Reply, error) {
	logger := log.WithField("func", "RemoveLocalEndpoint")

	defer recoverPanic(logger)

	out := &proto.Reply{
		Successful: true,
	}

	server := NewApiServer()

	/*
		Currently supporting policies for dpdk target only
	*/

	if server.config.InterfaceType != "tap" {
		return out, nil
	}

	if in == nil || reflect.DeepEqual(*in, proto.WorkloadEndpointRemove{}) {
		err := errors.New("Empty remove local endpoint request")
		logger.Errorf("Empty remove local endpoint request.")
		out.Successful = false
		return out, err
	}

	logger.Infof("Incoming RemoveLocalEndpoint Request %+v", in)

	if ReplaySet() || !Infrap4d.Running() {
		log.Infof("Infrap4d is not running, waiting to restart")
		// Wait till timeout for the infrap4d to restart
		ret := Infrap4d.WaitToRestart(server.config.Infrap4dTimeout)
		if ret == false {
			out.Successful = false
			return out, errors.New("Infrap4d is not running")
		}
		log.Infof("Infrap4d is running now")
	}

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
		logger.Errorf("Failed to delete policies for endpoint %s from the pipeline",
			in.Id.WorkloadId)
		err := fmt.Errorf("Failed delete policies for endpoint %s from the pipeline",
			in.Id.WorkloadId)
		out.Successful = false
		return out, err
	}

	if ok := workerEp.DeleteFromStore(); !ok {
		logger.Errorf("Failed to delete policies for endpoint %s from the store",
			in.Id.WorkloadId)
		err := fmt.Errorf("Failed to delete policies for endpoint %s from the store",
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

	defer recoverPanic(logger)

	out := &proto.Reply{
		Successful: true,
	}

	if in == nil || reflect.DeepEqual(*in, proto.SetupHostInterfaceRequest{}) {
		out.Successful = false
		logger.Errorf("Empty SetupHostInterface request")
		return out, errors.New("Empty SetupHostInterface request")
	}

	logger.Infof("Incoming SetupHostInterface request %s", in.String())

	server := NewApiServer()

	if ReplaySet() || !Infrap4d.Running() {
		log.Infof("Infrap4d is not running, waiting to restart")
		// Wait till timeout for the infrap4d to restart
		ret := Infrap4d.WaitToRestart(server.config.Infrap4dTimeout)
		if ret == false {
			out.Successful = false
			return out, errors.New("Infrap4d is not running")
		}
		log.Infof("Infrap4d is running now")
	}

	updateHostIP := false
	updateNodeIP := false

	if len(s.config.NodeIP) == 0 {
		logger.Errorf("No node ip address configured")
		err = fmt.Errorf("No node ip address configured")
		out.Successful = false
		return out, err
	}

	ipAddr := strings.Split(in.Ipv4Addr, "/")[0]
	if net.ParseIP(ipAddr) == nil {
		logger.Errorf("Invalid IP address: %s, err: %v", ipAddr, err)
		out.Successful = false
		return out, err
	}

	macAddr := in.MacAddr
	macAddress, err := net.ParseMAC(macAddr)
	if err != nil {
		logger.Errorf("Invalid MAC address: %s, err: %v", macAddr, err)
		out.Successful = false
		return out, err
	}

	portID, err := getPortID(in.IfName, macAddress)
	if err != nil {
		logger.Errorf("Failed to get port id for %s, err: %v",
			in.IfName, err)
		out.Successful = false
		return out, err
	}

	logger.Debugf("Interface: %s, port id: %d", in.IfName, portID)

	/*
		The inframanger has received the host interface information
		for the first time. Update the pipeline with the entries
	*/

	if len(hostInterface.Mac) == 0 {
		updateHostIP = true
		updateNodeIP = true
	}

	/*
		If the infraagent has been restarted for some reason,
		the inframanager receives the request again. Check and match with
		the new entries, delete and update the new ip and mac.
	*/
	if len(hostInterface.Ip) != 0 && hostInterface.Ip != ipAddr {
		logger.Infof("Host Interface ip has changed")

		ep := store.EndPoint{
			PodIpAddress: hostInterface.Ip,
		}

		entry := ep.GetFromStore()
		if entry != nil {
			epEntry := entry.(store.EndPoint)
			logger.Infof("Deleting old ip entry")
			// Delete the old host IP entry. Ignore any errors.
			p4.DeleteCniRules(ctx, server.p4RtC, epEntry)
		}
		updateHostIP = true

	}

	if len(hostInterface.Mac) != 0 && hostInterface.Mac != macAddr {
		logger.Infof("Host Interface mac has changed")

		ep := store.EndPoint{
			PodIpAddress: hostInterface.Ip,
		}

		entry := ep.GetFromStore()
		if entry != nil {
			epEntry := entry.(store.EndPoint)
			logger.Infof("Deleting old mac entry with host ip")
			// Delete the old host IP entry. Ignore any errors.
			p4.DeleteCniRules(ctx, server.p4RtC, epEntry)
		}

		ep = store.EndPoint{
			PodIpAddress: s.config.NodeIP,
		}

		entry = ep.GetFromStore()
		if entry != nil {
			epEntry := entry.(store.EndPoint)
			logger.Infof("Deleting old mac entry with node ip")
			// Delete the old node IP entry. Ignore any errors.
			p4.DeleteCniRules(ctx, server.p4RtC, epEntry)
		}
		updateHostIP = true
		updateNodeIP = true

	}

	if updateHostIP {
		if status, err := insertRule(s.log, ctx, server.p4RtC, macAddr,
			ipAddr, portID, p4.HOST); err != nil {
			logger.Errorf("Failed to insert rule to the pipeline ip: %s mac: %s port id: %d err: %v",
				ipAddr, macAddr, portID, err)
			out.Successful = status
			return out, err
		}
	}

	if updateNodeIP {
		status, err := insertRule(s.log, ctx, server.p4RtC, macAddr,
			s.config.NodeIP, portID, p4.HOST)
		if err != nil {
			logger.Errorf("Failed to insert rule to the pipeline p: %s mac: %s port id: %d err: %v",
				s.config.NodeIP, macAddr, portID, err)
			out.Successful = status
			return out, err
		}
	}

	hostInterface.Ip = ipAddr
	hostInterface.Mac = macAddr

	/* Add to store */
	store.SetHostInterface(in.IfName, ipAddr, macAddr)

	return out, nil
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
