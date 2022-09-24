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

package netconf

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/ipdk-io/k8s-infra-offload/pkg/pool"
	"github.com/ipdk-io/k8s-infra-offload/pkg/types"
	"github.com/ipdk-io/k8s-infra-offload/pkg/utils"
	pb "github.com/ipdk-io/k8s-infra-offload/proto"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/vishvananda/netlink"
)

type tapPodInterface struct {
	log  *logrus.Entry
	pool pool.ResourcePool
}

func NewTapPodInterface(log *logrus.Entry) (types.PodInterface, error) {
	pi := &tapPodInterface{log: log}
	if err := pi.setup(); err != nil {
		log.WithError(err).Error("failed to setup tap interface")
		return nil, err
	}
	return pi, nil
}

func (pi *tapPodInterface) setup() error {
	tapPrefix := viper.GetString("tapPrefix")
	pi.log.Infof("Scanning for Host Tap for interfaces using prefix %s", tapPrefix)
	intfs, err := utils.GetTapInterfaces(tapPrefix)
	if err != nil {
		pi.log.Error("empty resource pool, Pod network interface will not be configured")
		return err
	}
	pi.log.Infof("Found %v of host Tap interfaces", len(intfs))
	if len(intfs) == 0 {
		return fmt.Errorf("failed to discover host Tap interfaces with prefix %s", tapPrefix)
	}

	pi.log.Infof("Interface list:")
	for _, intf := range intfs {
		pi.log.Infof("Interface Name: %s Mac: %s", intf.InterfaceName, intf.MacAddr)
	}

	pool := pool.NewResourcePool(intfs)
	pi.pool = pool
	// get one interface for host networking and assign first address
	res, err := pi.pool.Get()
	if err != nil {
		pi.log.WithError(err).Error("unable to allocate interface for host")
		return err
	}

	ipnet, err := pi.getHostIPfromPodCIDR()
	if err != nil {
		pi.log.WithError(err).Error("Failed to get IP for host interface")
		return err
	}
	pi.log.Printf("Host IP address allocated: %s", ipnet)

	if err := pi.configureHostInterface(res.InterfaceInfo.InterfaceName, ipnet, intfs); err != nil {
		return fmt.Errorf("Failed to configure host interface %s with IP configurations", res.InterfaceInfo.InterfaceName)
	}
	// set host interface name
	types.NodeInfraHostInterfaceName = res.InterfaceInfo.InterfaceName
	return nil
}

func (pi *tapPodInterface) configureHostInterface(ifName string, ipnet *net.IPNet, interfaces []*types.InterfaceInfo) error {

	link, err := netlink.LinkByName(ifName)
	if err != nil {
		pi.log.WithError(err).Errorf("error getting netlink object with inteface name: %s", ifName)
		return err
	}
	// delete any set address on interface
	ips, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		pi.log.WithError(err).Error("Failed to list IPs on interface")
		return err
	}
	for _, ip := range ips {
		if err := netlink.AddrDel(link, &ip); err != nil {
			pi.log.WithError(err).Error("Failed to remove ip address")
		}
	}

	if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: ipnet}); err != nil {
		pi.log.WithError(err).Error("Failed to set ip address for interface")
		return err
	}
	if err := netlink.LinkSetUp(link); err != nil {
		pi.log.WithError(err).Error("Failed to set interface up")
		return err
	}
	// setup routing from pods CIDR via host side tap interface
	// check if it exist already
	if err := pi.configureRouting(link); err != nil {
		pi.log.WithError(err).Error("Failed to configure routing")
		return err
	}
	return nil
}

func (pi *tapPodInterface) configureRouting(link netlink.Link) error {
	// get first address from Pod CIDR
	// TODO add ipv6 support
	pi.log.Infof("Cluster CIDR %s", types.ClusterPodsCIDR)
	clusterIP, err := netlink.ParseAddr(types.ClusterPodsCIDR)
	if err != nil {
		return err
	}

	pi.log.Infof("Node Pods CIDR %s", types.NodePodsCIDR)
	nodePodsIP, err := netlink.ParseAddr(types.NodePodsCIDR)
	if err != nil {
		return err
	}

	// setup routing from pods CIDR via VF[0]
	// check if it exist already
	if err := setupHostRoute(clusterIP.IPNet, link); err != nil {
		return fmt.Errorf("Failed to setup route to Cluster CIDR: %w", err)
	}

	if err := setupHostRoute(nodePodsIP.IPNet, link); err != nil {
		return fmt.Errorf("Failed to setup route to Pods CIDR: %w", err)
	}

	return nil
}

func (pi *tapPodInterface) getHostIPfromPodCIDR() (*net.IPNet, error) {
	varConfigurer := utils.NewOsVariableConfigurer()
	ec := utils.NewEnvConfigurer(varConfigurer, types.DefaultCalicoConfig)
	// try to release any address allocated for Infra Agent, ignore error just print
	if err := utils.ReleaseIPFromIPAM(ec, ipam.ExecDel); err != nil {
		pi.log.WithError(err).Error("Failed to release allocated address")
	}

	ipnet, err := utils.GetIPFromIPAM(ec, ipam.ExecAdd)
	if err != nil {
		return nil, err
	}

	return ipnet, nil
}

func (pi *tapPodInterface) CreatePodInterface(in *pb.AddRequest) (*types.InterfaceInfo, error) {
	res, err := pi.pool.Get()
	if err != nil {
		pi.log.Errorf("failed to get a free interface for pod error: %v", err)
		return nil, err
	}
	pi.log.Infof("Interface allocated for Pod: %s", res.InterfaceInfo.InterfaceName)

	if err := setHostInterfaceInPodNetns(in, res.InterfaceInfo); err != nil {
		if _, ok := err.(nsError); ok {
			movePodInterfaceToHostNetns(in.Netns, in.InterfaceName, res.InterfaceInfo)
		}
		pi.log.WithError(err).Error("failed to push interface to container")
		pi.pool.Release(res.InterfaceInfo.InterfaceName) // if we failed to setup the allocated interface then release it
		return nil, err
	}
	pi.log.Infof("Host interface name: %s interface mac %s", res.InterfaceInfo.InterfaceName, res.InterfaceInfo.MacAddr)

	refid := filepath.Base(in.Netns)
	if err = utils.SaveInterfaceConf(utils.GetDataDirPath(types.TapInterface), refid, in.InterfaceName, res.InterfaceInfo); err != nil {
		pi.log.WithError(err).Error("storing cache failed")
		return nil, err
	}
	return res.InterfaceInfo, nil
}

func (pi *tapPodInterface) ReleasePodInterface(in *pb.DelRequest) error {
	// release used interface
	refid := filepath.Base(in.Netns)
	conf, err := utils.ReadInterfaceConf(utils.GetDataDirPath(types.TapInterface), refid, in.InterfaceName)
	if err != nil {
		if os.IsNotExist(err) {
			pi.log.WithError(err).Infof("interface config cache file for refid %s is not found", refid)
			return nil // If cache file does not exist, then most like pod interface was not created by agent or may have been deleted. Nothing else to do for us
		}
		return err
	}
	if err := movePodInterfaceToHostNetns(in.Netns, in.InterfaceName, conf); err != nil {
		return err
	}
	pi.pool.Release(conf.InterfaceName)
	// remove cache, ignore error
	path := filepath.Join(utils.GetDataDirPath(types.TapInterface), refid+"-"+in.InterfaceName)
	_ = os.Remove(path)
	return nil
}

func (pi *tapPodInterface) SetupNetwork(ctx context.Context, c pb.InfraAgentClient, intfInfo *types.InterfaceInfo, in *pb.AddRequest) (*pb.AddReply, error) {
	request := &pb.CreateNetworkRequest{
		AddRequest: in,
		HostIfName: in.DesiredHostInterfaceName,
		MacAddr:    intfInfo.MacAddr,
	}
	// Note: We may need to call different InfraAgentClient method for Tap with different payloads
	out, err := c.CreateNetwork(ctx, request)
	if err != nil {
		return nil, err
	}

	return out, nil
}

func (pi *tapPodInterface) ReleaseNetwork(ctx context.Context, c pb.InfraAgentClient, in *pb.DelRequest) (*pb.DelReply, error) {
	out := &pb.DelReply{
		Successful: true,
	}
	// get interface config from cache
	refid := filepath.Base(in.Netns)
	conf, err := utils.ReadInterfaceConf(utils.GetDataDirPath(types.TapInterface), refid, in.InterfaceName)
	if err != nil {
		if os.IsNotExist(err) {
			pi.log.WithError(err).Infof("interface config cache file for refid %s is not found", refid)
			return out, nil // If cache file not exist, then most like pod interface was not created by agent or may have been deleted
		}
		pi.log.WithError(err).Errorf("error trying to read interface config from cache file using refid %s", refid)
		out.Successful = false
		out.ErrorMessage = err.Error()
		return out, err
	}
	var ip string = ""
	// fetch interface IP
	err = ns.WithNetNSPath(in.Netns, func(_ ns.NetNS) error {
		linkObj, err := netlink.LinkByName(in.InterfaceName)
		if err != nil {
			pi.log.WithError(err).Errorf("failed to find netlink device with name %s", in.InterfaceName)
			return err
		}
		l, err := netlink.AddrList(linkObj, netlink.FAMILY_V4)
		if err != nil || len(l) == 0 {
			pi.log.WithError(err).Error("Failed to fetch IP address from Pod interface or IP not set")
		}
		ip = l[0].IPNet.String()
		return nil
	})
	if err != nil {
		_, ok := err.(ns.NSPathNotExistErr)
		if ok {
			// namespace already gone do not return error
			return out, nil
		}
		pi.log.WithError(err).Errorf("failed to enter Pod network nampespace with id: %s", in.Netns)
		out.Successful = false
		out.ErrorMessage = err.Error()
		return out, err
	}
	request := &pb.DeleteNetworkRequest{
		DelRequest: in,
		HostIfName: conf.InterfaceName,
		MacAddr:    conf.MacAddr,
		Ipv4Addr:   ip,
	}

	return c.DeleteNetwork(ctx, request)
}
