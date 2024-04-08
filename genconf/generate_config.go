package main

import (
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ipdk-io/k8s-infra-offload/pkg/inframanager/config"
	conf "github.com/ipdk-io/k8s-infra-offload/pkg/inframanager/config"
	"github.com/ipdk-io/k8s-infra-offload/pkg/types"
	"github.com/ipdk-io/k8s-infra-offload/pkg/utils"
	"gopkg.in/yaml.v2"
)

type Conf struct {
	InterfaceType      string           `yaml:"InterfaceType,omitempty"`
	Interface          string           `yaml:"Interface,omitempty"`
	HostIfaceMTU       string           `yaml:"HostIfaceMTU,omitempty"`
	Conn               string           `yaml:"Conn,omitempty"`
	LogLevel           string           `yaml:"LogLevel,omitempty"`
	Services           bool             `yaml:"Services,omitempty"`
	Policy             bool             `yaml:"Policy,omitempty"`
	InfraManager       conf.ManagerConf `yaml:"InfraManager,omitempty"`
	Infrap4dGrpcServer conf.ServerConf  `yaml:"Infrap4dGrpcServer,omitempty"`
	Infrap4dGnmiServer conf.ServerConf  `yaml:"Infrap4dGnmiServer,omitempty"`
	DeviceId           uint64           `yaml:"DeviceId,omitempty"`
	DBTicker           uint32           `yaml:"DBTicker,omitempty"`
}

type AgentConf struct {
	InterfaceType string `yaml:"interfaceType,omitempty"`
	Iface         string `yaml:"interface,omitempty"`
	HostIfaceMTU  string `yaml:"hostIfaceMTU,omitempty"`
	Insecure      bool   `yaml:"insecure,omitempty"`
	Mtls          bool   `yaml:"mtls,omitempty"`
	LogLevel      string `yaml:"logLevel,omitempty"`
	ManagerAddr   string `yaml:"managerAddr,omitempty"`
	ManagerPort   string `yaml:"managerPort,omitempty"`
	Services      bool   `yaml:"services,omitempty"`
	Policy        bool   `yaml:"policy,omitempty"`
}

func mgrGetDefault() conf.ManagerConf {
	return conf.ManagerConf{
		Addr: "127.0.0.1:50002",
		Conn: "mtls",
	}
}

func infrap4dGetGnmiDefault() conf.ServerConf {
	gnmiServer := conf.ServerConf{
		Addr: "localhost:9339",
		Conn: "mtls",
	}
	return gnmiServer
}

func infrap4dGetGrpcDefault() conf.ServerConf {
	grpcServer := conf.ServerConf{
		Addr: "localhost:9559",
		Conn: "mtls",
	}
	return grpcServer
}

func validIfaceType(ifaceType string) bool {
	switch ifaceType {
	case types.SriovPodInterface, types.TapInterface, types.CDQInterface:
		return true
	default:
		return false
	}
}

func validateIpAddrPort(ipAddrPort string) {
	fields := strings.Split(ipAddrPort, ":")
	if len(fields) != 2 {
		log.Fatalf("Invalid address and port specified: %s", ipAddrPort)
	}
	ipAddr := fields[0]
	p := fields[1]

	if ipAddr != "localhost" {
		if net.ParseIP(ipAddr) == nil {
			log.Fatalf("Invalid ip address specified: %s", ipAddr)
		}
	}

	port, err := strconv.Atoi(p)
	if err != nil || port < 0 || port > 65535 {
		log.Fatalf("Invalid port specified: %s", p)
	}

}

func validateInfraMgrParams(mgr config.ManagerConf) {
	validateIpAddrPort(mgr.Addr)

	if len(mgr.ArpMac) > 0 {
		if _, err := net.ParseMAC(mgr.ArpMac); err != nil {
			log.Fatalf("Invalid arp mac address %s, err: %v", mgr.ArpMac, err)
		}
	}

	if !utils.ValidCiphers(mgr.CipherSuites) {
		log.Fatal("Invalid ciphers provided for inframanager server")
	}
}

func validateConfigs(cConf Conf) {
	if !validIfaceType(cConf.InterfaceType) {
		log.Fatalf("Invalid interface type: %s", cConf.InterfaceType)
	}
	mtu, err := strconv.Atoi(cConf.HostIfaceMTU)
	if err != nil || mtu < 576 || mtu > 9000 {
		log.Fatalf("Invalid mtu size: %s", cConf.HostIfaceMTU)
	}
	if cConf.InterfaceType == types.TapInterface && mtu != types.TapInterfaceMTU {
		log.Fatalf("Invalid mtu size: %s for %s. Use %d",
			cConf.HostIfaceMTU, types.TapInterface, types.TapInterfaceMTU)
	}
	if cConf.InterfaceType == types.CDQInterface || cConf.InterfaceType == types.SriovPodInterface {
		if len(cConf.InfraManager.ArpMac) == 0 {
			log.Fatalf("Missing arpMac field. Please provide proper input")
		}
	}
	if utils.GetConnType(cConf.Conn) == utils.UnknownConn {
		log.Fatalf("Invalid connection type: %s", cConf.Conn)
	}

	if !utils.ValidLogLevel(cConf.LogLevel) {
		log.Fatalf("Invalid log level: %s", cConf.LogLevel)
	}

	validateInfraMgrParams(cConf.InfraManager)
	validateIpAddrPort(cConf.Infrap4dGrpcServer.Addr)
	validateIpAddrPort(cConf.Infrap4dGnmiServer.Addr)

	if utils.GetConnType(cConf.Infrap4dGrpcServer.Conn) == utils.UnknownConn {
		log.Fatalf("Invalid connection type: %s for infrap4d grpc server", cConf.Infrap4dGrpcServer.Conn)
	}
	if utils.GetConnType(cConf.Infrap4dGnmiServer.Conn) == utils.UnknownConn {
		log.Fatalf("Invalid connection type: %s for infrap4d gnmi server", cConf.Infrap4dGnmiServer.Conn)
	}

}

func main() {
	var cConf Conf

	ex, err := os.Executable()
	if err != nil {
		log.Fatal("Failed to get the path of the executable")
	}
	exPath := filepath.Dir(ex)
	configFile := filepath.Join(exPath, "../deploy/", "common-config.yaml")
	agentFile := filepath.Join(exPath, "../deploy/", "infraagent-config.yaml")
	mgrFile := filepath.Join(exPath, "../deploy/", "inframanager-config.yaml")

	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Fatalf("Failed to read common-config: %s", configFile)
	}

	err = yaml.Unmarshal(data, &cConf)
	if err != nil {
		log.Fatalf("Failed to unmarshal data from the file: %s", configFile)
	}

	if len(cConf.InterfaceType) == 0 {
		cConf.InterfaceType = types.CDQInterface
	}
	if len(cConf.HostIfaceMTU) == 0 {
		cConf.HostIfaceMTU = strconv.Itoa(types.DefaultMTU)
	}

	if cConf.InterfaceType == types.TapInterface {
		cConf.Interface = ""
	}

	validateConfigs(cConf)

	agentConf := AgentConf{
		InterfaceType: cConf.InterfaceType,
		Iface:         cConf.Interface,
		HostIfaceMTU:  cConf.HostIfaceMTU,
		LogLevel:      cConf.LogLevel,
		Services:      cConf.Services,
		Policy:        cConf.Policy,
	}
	switch cConf.Conn {
	case "insecure":
		agentConf.Insecure = true
		agentConf.Mtls = false
	case "tls":
		agentConf.Insecure = false
		agentConf.Mtls = false
	case "mtls":
		agentConf.Insecure = false
		agentConf.Mtls = true
	default:
		log.Fatalf("Invalid connection type: %s", cConf.Conn)
	}

	fields := strings.Split(cConf.InfraManager.Addr, ":")
	agentConf.ManagerAddr = fields[0]
	agentConf.ManagerPort = fields[1]

	// If services is enabled, disable policy
	if agentConf.Services {
		agentConf.Policy = false
	}
	// If policy is enabled, disable services
	if agentConf.Policy {
		agentConf.Services = false
	}

	agentData, err := yaml.Marshal(&agentConf)
	if err != nil {
		log.Fatal("Failed to marshal agent data")
	}

	if ioutil.WriteFile(agentFile, agentData, 0644) != nil {
		log.Fatalf("Failed to write configuration to %s", agentFile)
	}

	if cConf.InterfaceType == types.TapInterface {
		cConf.InfraManager.ArpMac = ""
	}

	if cConf.InfraManager.DBTicker == 0 {
		cConf.InfraManager.DBTicker = types.DBTicker
	}

	mgr := mgrGetDefault()
	mgr.Addr = cConf.InfraManager.Addr
	mgr.Conn = cConf.Conn
	mgr.ArpMac = cConf.InfraManager.ArpMac
	mgr.CipherSuites = cConf.InfraManager.CipherSuites
	mgr.DBTicker = cConf.InfraManager.DBTicker

	mgrConf := conf.Configuration{
		Infrap4dGrpcServer: cConf.Infrap4dGrpcServer,
		Infrap4dGnmiServer: cConf.Infrap4dGnmiServer,
		InfraManager:       mgr,
		Services:           cConf.Services,
		Policy:             cConf.Policy,
		InterfaceType:      cConf.InterfaceType,
		LogLevel:           cConf.LogLevel,
		DeviceId:           cConf.DeviceId,
	}

	mgrData, err := yaml.Marshal(mgrConf)
	if err != nil {
		log.Fatal("Failed to marshal manager data")
	}

	if ioutil.WriteFile(mgrFile, mgrData, 0644) != nil {
		log.Fatalf("Failed to write configuration to %s", mgrFile)
	}

}
