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

package utils

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	cniTypes "github.com/containernetworking/cni/pkg/types"
	cniv1 "github.com/containernetworking/cni/pkg/types/100"

	"github.com/ipdk-io/k8s-infra-offload/pkg/types"
	"github.com/vishvananda/netlink"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

const (
	// SysClassNet is a directory for network interface data
	SysClassNet = "/sys/class/net"

	serviceSubnetPattern = `(--service-cluster-ip-range=)(?:[0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}`
	podSubnetPattern     = `(--cluster-cidr=)(?:[0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}`

	kubeControllerManagerName = "kube-controller-manager"
)

var (
	restInClusterConfig = rest.InClusterConfig

	envVariables = map[string]string{
		"CNI_PATH":        types.DefaultCNIBinPath,
		"CNI_IFNAME":      "eth0",
		"CNI_NETNS":       types.InfraDummyNetNS,
		"CNI_CONTAINERID": types.InfraHostDummyContainerId,
	}
)

func SaveInterfaceConf(dataDir, refid, podIface string, conf *types.InterfaceInfo) error {
	confBytes, err := json.Marshal(conf)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(dataDir, 0700); err != nil {
		return err
	}
	path := filepath.Join(dataDir, refid+"-"+podIface)
	return os.WriteFile(path, confBytes, 0600)
}

func ReadInterfaceConf(dataDir, refid, podIface string) (*types.InterfaceInfo, error) {
	path := filepath.Join(dataDir, refid+"-"+podIface)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	conf := &types.InterfaceInfo{}
	if err = json.Unmarshal(data, conf); err != nil {
		return nil, err
	}
	return conf, nil
}

func CleanIntfConfCache(dataDir, refid, podIface string) error {
	path := filepath.Join(dataDir, refid+"-"+podIface)
	return os.Remove(path)
}

func GetNodeIP(client kubernetes.Interface, nodeName string) (string, error) {
	nodes, err := client.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{
		FieldSelector: "metadata.name=" + nodeName})
	if err != nil {
		panic(err.Error())
	}

	if len(nodes.Items) == 0 {
		return "", errors.New("unable to get K8s node from API")
	}

	var internalIP string
	for _, adr := range nodes.Items[0].Status.Addresses {
		if adr.Type == v1.NodeInternalIP {
			internalIP = adr.Address
		}
	}

	if internalIP == "" {
		return "", errors.New("empty node InternalIP")
	}
	return internalIP, nil
}

type InterfaceAddressGetter interface {
	GetAddr(net.Interface) ([]net.Addr, error)
}

type DefaultInterfaceAddressGetter struct{}

func (g *DefaultInterfaceAddressGetter) GetAddr(ifc net.Interface) ([]net.Addr, error) {
	return ifc.Addrs()
}

func getInterface(ifaceList []net.Interface, internalIP string, ifAddressGetter InterfaceAddressGetter) (string, error) {
	var ifaceName string
	for _, i := range ifaceList {
		addrs, err := ifAddressGetter.GetAddr(i)
		if err != nil {
			log.Printf("Unable to get Addrs for interface %v err:%v", i.Name, err)
			continue
		}
		for _, addr := range addrs {
			if strings.HasPrefix(addr.String(), internalIP) {
				ifaceName = i.Name
			}
		}
	}

	if ifaceName == "" {
		return "", errors.New("master interface not found")
	}
	return ifaceName, nil
}

func GetNodeNetInterface(k8sclient kubernetes.Interface, nodeName string, ifGetter InterfaceAddressGetter) (string, error) {
	internalIP, err := GetNodeIP(k8sclient, nodeName)
	if err != nil {
		return "", err
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	return getInterface(ifaces, internalIP, ifGetter)
}

func GetK8sConfig() (*rest.Config, error) {
	clusterConfig, err := restInClusterConfig()
	if err == nil {
		return clusterConfig, nil
	}
	var kubeconfig string
	if home := homedir.HomeDir(); home != "" {
		kubeconfig = filepath.Join(home, ".kube", "config")
	}
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, err
	}
	return config, nil
}

func GetNodeName() (string, error) {
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		return "", errors.New("unable to get K8s node name from ENV var NODE_NAME")
	}
	return nodeName, nil
}

// GetVFList returns SRIO-VF for given pf network interface name
// when prefix will be not empty it will be prepended before default
// "/sys/class/net" directory name
func GetVFList(pf string, prefix string) ([]*types.InterfaceInfo, error) {
	out := make([]*types.InterfaceInfo, 0)
	devicePath := path.Join(prefix, pf, "device")
	de, err := os.ReadDir(devicePath)
	if err != nil {
		return nil, err
	}

	for _, entry := range de {
		if strings.Contains(entry.Name(), "virtfn") {
			linkPath := path.Join(devicePath, entry.Name())
			realPath, err := os.Readlink(linkPath)
			if err != nil {
				continue
			}
			vfPciAddr := path.Base(realPath) // get vf pciAddr

			r := regexp.MustCompile(`(?m)(\d+)$`) // get vfid from link name
			vfIdStr := r.FindString(entry.Name())
			vfId, _ := strconv.Atoi(vfIdStr)

			netPath := path.Join(devicePath, entry.Name(), "net") // get vf interface name
			netEntry, err := os.ReadDir(netPath)
			if err != nil {
				continue
			}

			if len(netEntry) == 0 {
				// vf probably does not exists in root netns, ommit
				continue
			}
			ifaceName := netEntry[0].Name()

			addressPath := path.Join(netPath, netEntry[0].Name(), "address") // get vf interface mac address
			mac, err := os.ReadFile(addressPath)
			if err != nil {
				continue
			}
			macStr := strings.Trim(string(mac), "\n")
			out = append(out, &types.InterfaceInfo{PciAddr: vfPciAddr, VfID: vfId, InterfaceName: ifaceName, MacAddr: macStr})
		}
	}
	// sort using vfid as a field
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].VfID < out[j].VfID
	})
	return out, nil
}

// GetTapInterfaces returns a list of host Tap interance info matching a naming prefix using "prefix"
func GetTapInterfaces(prefix string) ([]*types.InterfaceInfo, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("unable to get interface list: %s", err)
	}

	intfList := make([]*types.InterfaceInfo, 0)
	for _, link := range links {
		if strings.HasPrefix(link.Attrs().Name, prefix) {
			intfInfo := &types.InterfaceInfo{
				InterfaceName: link.Attrs().Name,
				MacAddr:       link.Attrs().HardwareAddr.String(),
			}
			intfList = append(intfList, intfInfo)
		}
	}
	return intfList, nil
}

func GetNodePodsCIDR(k8sclient kubernetes.Interface, nodeName string) (string, error) {
	ns, err := k8sclient.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{
		FieldSelector: "metadata.name=" + nodeName})
	if err != nil {
		return "", err
	}
	if len(ns.Items) == 0 {
		return "", fmt.Errorf("empty node list for %s", nodeName)
	}
	return ns.Items[0].Spec.PodCIDR, nil
}

func GetK8sClient(config *rest.Config) (kubernetes.Interface, error) {
	return kubernetes.NewForConfig(config)
}

func getIPFromCommand(pattern string, command []string) string {
	re := regexp.MustCompile(pattern)
	for _, cmd := range command {
		m := re.FindString(cmd)
		if len(m) == 0 {
			continue
		}

		split := strings.Split(m, "=")
		if len(split) != 2 {
			continue
		}
		return split[1]
	}
	return ""
}

// GetSubnets gets service and pod subnet
func GetSubnets(client kubernetes.Interface) error {
	pods, err := client.CoreV1().Pods("").List(context.TODO(),
		metav1.ListOptions{LabelSelector: fmt.Sprintf("%s=%s", "component", kubeControllerManagerName)})
	if err != nil {
		return err
	}

	if len(pods.Items) < 1 {
		return fmt.Errorf("unable to find %s pod", kubeControllerManagerName)
	}

	command := getCommandFromPod(pods, kubeControllerManagerName, kubeControllerManagerName)
	if command == nil || len(command) < 1 || command[0] == "" {
		return fmt.Errorf("unable to get command from %s pod", kubeControllerManagerName)
	}

	types.ClusterServicesSubnet = getIPFromCommand(serviceSubnetPattern, command)
	types.ClusterPodsCIDR = getIPFromCommand(podSubnetPattern, command)
	if len(types.ClusterServicesSubnet) == 0 || len(types.ClusterPodsCIDR) == 0 {
		// this is an error
		return fmt.Errorf("failed to get cluster pods cidr or service subnet from cluster configuration")
	}
	return nil
}

func setupRequiredEnvironment(ec *EnvConfigurer) ([]byte, error) {
	if err := ec.setupEnvVariables(envVariables); err != nil {
		return nil, err
	}

	return ec.readCalicoConfig()
}

type ipamExecAddFunc func(plugin string, netconf []byte) (cniTypes.Result, error)

// GetIPFromIPAM will request IP address from host-local IPAM, it will be used
// as infra host interface
func GetIPFromIPAM(ec *EnvConfigurer, ipamExecAdd ipamExecAddFunc) (*net.IPNet, error) {
	newConfBs, err := setupRequiredEnvironment(ec)
	if err != nil {
		return nil, err
	}
	res, err := ipamExecAdd("host-local", newConfBs)
	if err != nil {
		return nil, err
	}
	// Convert the IPAM result into the current version.
	result, err := cniv1.NewResultFromResult(res)
	if err != nil {
		return nil, err
	}
	if len(result.IPs) == 0 {
		return nil, fmt.Errorf("failed to request IP from IPAM, IP not allocated")
	}
	return &result.IPs[0].Address, nil
}

type ipamExecDelFunc func(plugin string, netconf []byte) error

// ReleaseIPFromIPAM will release IP address assigned for Infra host interface
func ReleaseIPFromIPAM(ec *EnvConfigurer, ipamExecDel ipamExecDelFunc) error {
	newConfBs, err := setupRequiredEnvironment(ec)
	if err != nil {
		return err
	}
	return ipamExecDel("host-local", newConfBs)
}

type variableConfigurer interface {
	getenv(string) string
	setenv(string, string) error
}

type OsVariableConfigurer struct{}

type EnvConfigurer struct {
	varConf      variableConfigurer
	calicoConfig string
}

func (ovc *OsVariableConfigurer) getenv(key string) string {
	return os.Getenv(key)
}

func (ovc *OsVariableConfigurer) setenv(key, value string) error {
	return os.Setenv(key, value)
}

func (ec *EnvConfigurer) setupVariable(key, value string) error {
	if len(ec.varConf.getenv(key)) == 0 {
		return ec.varConf.setenv(key, value)
	}
	return nil
}

func (ec *EnvConfigurer) setupEnvVariables(variables map[string]string) error {
	for key, value := range variables {
		if err := ec.setupVariable(key, value); err != nil {
			return err
		}
	}
	return nil
}

func (ec *EnvConfigurer) readCalicoConfig() ([]byte, error) {
	bs, err := os.ReadFile(ec.calicoConfig)
	if err != nil {
		return nil, err
	}
	// create config for IPAM
	var data map[string]interface{}
	if err := json.Unmarshal(bs, &data); err != nil {
		return nil, err
	}
	newConf := make(map[string]interface{}, 0)
	newConf["name"] = data["name"]
	newConf["cniVersion"] = data["cniVersion"]
	plugins := data["plugins"].([]interface{})
	for _, p := range plugins {
		pluginData := p.(map[string]interface{})
		if pluginData["type"] == "calico" {
			ipamData := pluginData["ipam"].(map[string]interface{})
			if ipamData["subnet"] == "usePodCidr" {
				ipamData["subnet"] = types.NodePodsCIDR
				newConf["ipam"] = ipamData
			} else {
				newConf["ipam"] = ipamData
			}
		}
	}
	return json.Marshal(newConf)
}

// NewOsVariableConfigurer will return new variable configurer based on os package
func NewOsVariableConfigurer() *OsVariableConfigurer {
	return &OsVariableConfigurer{}
}

// NewEnvConfigurer will return new environment configurer
func NewEnvConfigurer(varCfg variableConfigurer, calicoConfig string) *EnvConfigurer {
	return &EnvConfigurer{
		varConf:      varCfg,
		calicoConfig: calicoConfig,
	}
}

func getCommandFromPod(pods *v1.PodList, podName, containerName string) []string {
	for _, pod := range pods.Items {
		if strings.Contains(pod.Name, podName) {
			for _, container := range pod.Spec.Containers {
				if strings.Contains(container.Name, containerName) {
					return container.Command
				}
			}
		}
	}
	return nil
}

// GetDataDirPath will return path to cache directory of given type
func GetDataDirPath(t string) string {
	return path.Join(types.DataDir, t)
}
