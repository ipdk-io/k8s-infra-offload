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
	"os"
	"path/filepath"

	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/ipdk-io/k8s-infra-offload/pkg/pool"
	"github.com/ipdk-io/k8s-infra-offload/pkg/types"
	"github.com/ipdk-io/k8s-infra-offload/pkg/utils"
	pb "github.com/ipdk-io/k8s-infra-offload/proto"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

type sriovPodInterface struct {
	log  *logrus.Entry
	pool pool.ResourcePool
}

func NewSriovPodInterface(log *logrus.Entry) (types.PodInterface, error) {
	pi := &sriovPodInterface{log: log}
	if err := pi.setup(); err != nil {
		log.WithError(err).Error("failed to setup SRIOV interface")
		return nil, err
	}
	return pi, nil
}

func (pi *sriovPodInterface) setup() error {
	if err := pi.initializePool(); err != nil {
		pi.log.WithError(err).Error("Cannot initialize sriov resource pool")
		return err
	}

	link, res, err := pi.perepareInterface()
	if err != nil {
		pi.log.WithError(err).Error("Cannot prepare sriov pod interface")
		return err
	}

	varConfigurer := utils.NewOsVariableConfigurer()
	ec := utils.NewEnvConfigurer(varConfigurer, types.DefaultCalicoConfig)

	// try to release any address allocated for Infra Agent, ignore error just print
	if err := utils.ReleaseIPFromIPAM(ec, ipam.ExecDel); err != nil {
		pi.log.WithError(err).Error("Failed to release allocated address")
	}

	ipnet, err := utils.GetIPFromIPAM(ec, ipam.ExecAdd)
	if err != nil {
		return err
	}
	pi.log.Printf("Got address for host Infra interface %s", ipnet)

	if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: ipnet}); err != nil {
		pi.log.WithError(err).Error("Failed to set ip address for interface")
		return err
	}
	if err := netlink.LinkSetUp(link); err != nil {
		pi.log.WithError(err).Error("Failed to set interface up")
		return err
	}

	if err := pi.configureRouting(link); err != nil {
		pi.log.WithError(err).Error("Failed to configure routing")
		return err
	}

	// set host interface name
	types.NodeInfraHostInterfaceName = res.InterfaceInfo.InterfaceName
	return nil
}

func (pi *sriovPodInterface) configureRouting(link netlink.Link) error {
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

func (pi *sriovPodInterface) initializePool() error {
	pi.log.Infof("Scanning for VF for interface %s", types.NodeInterfaceName)
	vfs, err := utils.GetVFList(types.NodeInterfaceName, utils.SysClassNet)
	if err != nil {
		pi.log.Error("empty resource pool, Pod network interface will not be configured")
		return err
	}
	pi.log.Infof("Found %v of VF(s)", len(vfs))
	if len(vfs) == 0 {
		return fmt.Errorf("failed to discover VF on interface %s", types.NodeInterfaceName)
	}
	pool := pool.NewResourcePool(vfs)
	pi.pool = pool
	return nil
}

func (pi *sriovPodInterface) perepareInterface() (netlink.Link, *pool.Resource, error) {
	// get first VF and assign first address
	res, err := pi.pool.Get()
	if err != nil {
		pi.log.WithError(err).Error("Cannot initialize sriov pod interface")
		return nil, nil, err
	}

	link, err := netlink.LinkByName(res.InterfaceInfo.InterfaceName)
	if err != nil {
		pi.log.WithError(err).Error("Error getting host interface")
		return nil, nil, err
	}
	// delete any set address on interface
	ips, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		pi.log.WithError(err).Error("Failed to list IPs on interface")
		return nil, nil, err
	}
	for _, ip := range ips {
		if err := netlink.AddrDel(link, &ip); err != nil {
			pi.log.WithError(err).Error("Failed to remove ip address")
		}
	}

	return link, res, err
}

func (pi *sriovPodInterface) CreatePodInterface(in *pb.AddRequest) (*types.InterfaceInfo, error) {
	res, err := pi.pool.Get()
	if err != nil {
		pi.log.Errorf("failed to get VF for pod error: %v", err)
		return nil, err
	}
	pi.log.Infof("Pod got resources: %+v", res)

	if err := DoSriovNetwork(in, res.InterfaceInfo); err != nil {
		// if error occured after interface was already moved into containers netns move it back
		if _, ok := err.(nsError); ok {
			movePodInterfaceToHostNetns(in.Netns, in.InterfaceName, res.InterfaceInfo)
		}
		pi.log.WithError(err).Error("failed to push interface to container")
		pi.pool.Release(res.InterfaceInfo.InterfaceName) // if we failed to setup the allocated interfrace then release it
		return nil, err
	}
	pi.log.Infof("Host interface name: %s interface mac %s", res.InterfaceInfo.InterfaceName, res.InterfaceInfo.MacAddr)

	refid := filepath.Base(in.Netns)
	if err = utils.SaveInterfaceConf(utils.GetDataDirPath(types.SriovPodInterface), refid, in.InterfaceName, res.InterfaceInfo); err != nil {
		pi.log.WithError(err).Error("storing cache failed")
		return nil, err
	}
	return res.InterfaceInfo, nil
}

func (pi *sriovPodInterface) ReleasePodInterface(in *pb.DelRequest) error {
	// release used VF
	dataDir := utils.GetDataDirPath(types.SriovPodInterface)
	refid := filepath.Base(in.Netns)
	conf, err := utils.ReadInterfaceConf(dataDir, refid, in.InterfaceName)
	if err != nil {
		return err
	}
	if err := movePodInterfaceToHostNetns(in.Netns, in.InterfaceName, conf); err != nil {
		return err
	}
	pi.pool.Release(conf.InterfaceName)
	// remove cache, ignore error
	path := filepath.Join(dataDir, refid+"-"+in.InterfaceName)
	_ = os.Remove(path)
	return nil
}

func (pi *sriovPodInterface) SetupNetwork(ctx context.Context, c pb.InfraAgentClient, intfInfo *types.InterfaceInfo, in *pb.AddRequest) (*pb.AddReply, error) {
	request := &pb.CreateNetworkRequest{
		AddRequest: in,
		HostIfName: in.DesiredHostInterfaceName,
		MacAddr:    intfInfo.MacAddr,
	}
	// Note: We may need to call different InfraAgentClient method for SRIOV VF with different payloads
	out, err := c.CreateNetwork(ctx, request)
	if err != nil {
		return nil, err
	}

	return out, nil
}

func (pi *sriovPodInterface) ReleaseNetwork(ctx context.Context, c pb.InfraAgentClient, in *pb.DelRequest) (*pb.DelReply, error) {
	out := &pb.DelReply{
		Successful: true,
	}
	// get interface config from cache
	refid := filepath.Base(in.Netns)
	conf, err := utils.ReadInterfaceConf(utils.GetDataDirPath(types.SriovPodInterface), refid, in.InterfaceName)
	if err != nil {
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
