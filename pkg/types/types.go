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

package types

import (
	"context"

	pb "github.com/ipdk-io/k8s-infra-offload/proto"
	"gopkg.in/tomb.v2"
)

const (
	ServerNetProto              = "tcp"
	InfraAgentAddr              = "127.0.0.1"
	InfraAgentPort              = "50001"
	DefaultInfraManagerAddr     = "127.0.0.1"
	DefaultInfraManagerPort     = "50002"
	ConnectionSocket            = "/var/run/calico/connection.sock"
	FelixDataplaneSocket        = "/var/run/calico/felix-dataplane.sock"
	DataDir                     = "/var/lib/cni/infraagent"
	InfraHost                   = "infra_host"
	SriovPodInterface           = "sriov"
	IpvlanPodInterface          = "ipvlan"
	TapInterface                = "tap"
	CDQInterface                = "cdq"
	TapInterfacePrefix          = "P4TAP_"
	InfraHostDummyContainerId   = "60e2aea2_2d40_44ac_b9b1_ace4ceda528e"
	InfraDummyNetNS             = "/var/run/netns/cni-60e2aea2-2d40-44ac-b9b1-ace4ceda528e"
	DefaultCNIBinPath           = "/opt/cni/bin"
	DefaultCalicoConfig         = "/etc/cni/net.d/10-calico.conflist"
	DefaultHealthServerPort     = "50096"
	CNIServerSocket             = "/var/run/calico/cni-server.sock"
	ServiceRefreshTimeInSeconds = 60
	ServerStatusOK              = "SERVING"
	ServerStatusStopped         = "STOPPED"
	InfraAgentLogDir            = "/var/log/infraagent"
	InfraAgentCLIName           = "infraagent"
	HostInterfaceRefId          = "hostInterface"
	DefaultRoute                = "169.254.1.1/32"
	HostInterfaceAddr           = "200.1.1.2/32"
	ArpProxyDefaultPort         = 0
	AgentDefaultClientCert      = "/etc/pki/infraagent/client/tls.crt"
	AgentDefaultClientKey       = "/etc/pki/infraagent/client/tls.key"
	AgentDefaultCACert          = "/etc/pki/infraagent/client/ca.crt"
	ManagerDefaultClientCert    = "/etc/pki/inframanager/client/tls.crt"
	ManagerDefaultClientKey     = "/etc/pki/inframanager/client/tls.key"
	ManagerDefaultServerCert    = "/etc/pki/inframanager/server/tls.crt"
	ManagerDefaultServerKey     = "/etc/pki/inframanager/server/tls.key"
	ManagerDefaultCACert        = "/etc/pki/inframanager/client/ca.crt"
	IfTtype                     = "cdq"
	P4InfoPath                  = "/share/infra/k8s_dp/p4Info.txt"
	P4BinPath                   = "/share/infra/k8s_dp/k8s_dp.pb.bin"
	Infrap4dTimeout             = 5
)

var (
	NodeName                   = ""
	NodeInterfaceName          = ""
	NodePodsCIDR               = ""
	NodeInfraHostInterfaceName = ""
	ClusterServicesSubnet      = ""
	ClusterPodsCIDR            = ""
	ServiceServerStatus        = ""
	CNIServerStatus            = ""
	InfraManagerServerStatus   = ""
	InfraManagerAddr           = ""
	InfraManagerPort           = ""
)

var HostInterfaceMTU int

type PodInterface interface {
	CreatePodInterface(in *pb.AddRequest) (*InterfaceInfo, error)
	ReleasePodInterface(in *pb.DelRequest) error
	SetupNetwork(context.Context, pb.InfraAgentClient, *InterfaceInfo, *pb.AddRequest) (*pb.AddReply, error)
	ReleaseNetwork(context.Context, pb.InfraAgentClient, *pb.DelRequest) (*pb.DelReply, error)
}

type Server interface {
	GetName() string
	StopServer()
	Start(t *tomb.Tomb) error
}

type InterfaceInfo struct {
	PciAddr       string `json:"pciaddr"`
	InterfaceName string `json:"interfacename"`
	VfID          int    `json:"vfid"`
	MacAddr       string `json:"macaddr"`
}
