package main

import (
	"io/ioutil"
	"log"
	"strconv"

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

func validCiphers(ciphers []string) bool {
	for _, c := range ciphers {
		_, ok := utils.CipherMap[c]
		if !ok {
			return false
		}
	}
	return true
}

func validIfaceType(ifaceType string) bool {
	switch ifaceType {
	case types.SriovPodInterface, types.TapInterface, types.CDQInterface:
		return true
	default:
		return false
	}
}

func main() {
	var cConf Conf
	configFile := "./deploy/common-config.yaml"
	agentFile := "./deploy/infraagent-config.yaml"
	mgrFile := "./deploy/inframanager-config.yaml"

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
	if !validIfaceType(cConf.InterfaceType) {
		log.Fatalf("Invalid interface type: %s", cConf.InterfaceType)
	}
	if len(cConf.HostIfaceMTU) == 0 {
		cConf.HostIfaceMTU = strconv.Itoa(types.DefaultMTU)
	}
	mtu, err := strconv.Atoi(cConf.HostIfaceMTU)
	if err != nil || mtu < 0 {
		log.Fatalf("Invalid mtu size: %s", cConf.HostIfaceMTU)
	}

	if cConf.InterfaceType == types.TapInterface {
		cConf.Interface = ""
	}
	agentConf := AgentConf{
		InterfaceType: cConf.InterfaceType,
		Iface:         cConf.Interface,
		HostIfaceMTU:  cConf.HostIfaceMTU,
		LogLevel:      cConf.LogLevel,
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

	agentData, err := yaml.Marshal(&agentConf)
	if err != nil {
		log.Fatal("Failed to marshal agent data")
	}

	if ioutil.WriteFile(agentFile, agentData, 0644) != nil {
		log.Fatalf("Failed to write configuration to %s", agentFile)
	}

	utils.CreateCipherMap()
	if !validCiphers(cConf.InfraManager.CipherSuites) {
		log.Fatal("Invalid ciphers provide for inframanager server")
	}

	if cConf.InterfaceType == types.TapInterface {
		cConf.InfraManager.ArpMac = ""
	}

	if cConf.DBTicker == 0 {
		cConf.DBTicker = types.DBTicker
	}

	mgr := mgrGetDefault()
	mgr.Addr = cConf.InfraManager.Addr
	mgr.Conn = cConf.Conn
	mgr.ArpMac = cConf.InfraManager.ArpMac
	mgr.CipherSuites = cConf.InfraManager.CipherSuites

	mgrConf := conf.Configuration{
		Infrap4dGrpcServer: cConf.Infrap4dGrpcServer,
		Infrap4dGnmiServer: cConf.Infrap4dGnmiServer,
		InfraManager:       mgr,
		InterfaceType:      cConf.InterfaceType,
		LogLevel:           cConf.LogLevel,
		DeviceId:           cConf.DeviceId,
		DBTicker:           cConf.DBTicker,
	}

	mgrData, err := yaml.Marshal(mgrConf)
	if err != nil {
		log.Fatal("Failed to marshal manager data")
	}

	if ioutil.WriteFile(mgrFile, mgrData, 0644) != nil {
		log.Fatalf("Failed to write configuration to %s", mgrFile)
	}

}
