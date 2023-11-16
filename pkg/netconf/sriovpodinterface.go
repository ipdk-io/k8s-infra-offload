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
	"path/filepath"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/ipdk-io/k8s-infra-offload/pkg/pool"
	"github.com/ipdk-io/k8s-infra-offload/pkg/types"
	"github.com/ipdk-io/k8s-infra-offload/pkg/utils"
	pb "github.com/ipdk-io/k8s-infra-offload/proto"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

var (
	getVFList          = utils.GetVFList
	doSriovNetworkFunc = doSriovNetwork
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

	_, ipnet, err := net.ParseCIDR(types.HostInterfaceAddr)

	if err != nil {
		pi.log.WithError(err).Error("Failed to get IP for host interface")
		return err
	}

	pi.log.Printf("Got address for host IPU interface %s", ipnet)

	if err := addrAdd(link, &netlink.Addr{IPNet: ipnet}); err != nil {
		pi.log.WithError(err).Error("Failed to set ip address for interface")
		return err
	}
	if err := linkSetUp(link); err != nil {
		pi.log.WithError(err).Error("Failed to set interface up")
		return err
	}

	if err := configureRoutingFunc(link, pi.log); err != nil {
		pi.log.WithError(err).Error("Failed to configure routing")
		return err
	}

	// set host interface name
	types.NodeInfraHostInterfaceName = res.InterfaceInfo.InterfaceName

	// dial inframmanger and setup host interface
	request := &pb.SetupHostInterfaceRequest{
		IfName:   types.NodeInfraHostInterfaceName,
		Ipv4Addr: ipnet.String(),
		MacAddr:  res.InterfaceInfo.MacAddr,
	}
	if err := sendSetupHostInterfaceFunc(request); err != nil {
		return err
	}

	return nil
}

func (pi *sriovPodInterface) initializePool() error {
	pi.log.Infof("Scanning for VF for interface %s", types.NodeInterfaceName)
	vfs, err := getVFList(types.NodeInterfaceName, utils.SysClassNet)
	if err != nil {
		pi.log.Error("empty resource pool, Pod network interface will not be configured")
		return err
	}
	pi.log.Infof("Found %v of VF(s)", len(vfs))
	if len(vfs) == 0 {
		return fmt.Errorf("failed to discover VF on interface %s", types.NodeInterfaceName)
	}
	pool := pool.NewResourcePool(vfs, utilsGetDataDirPath(types.SriovPodInterface))
	pi.pool = pool
	return nil
}

func (pi *sriovPodInterface) perepareInterface() (netlink.Link, *pool.Resource, error) {
	// get first VF and assign first address
	var res *pool.Resource
	// check if we have config in cache
	hostInterface, err := readInterfaceConf(utilsGetDataDirPath(types.TapInterface), types.HostInterfaceRefId, types.HostInterfaceRefId)
	if err != nil {
		// get one interface for host networking and assign first address
		res, err = pi.pool.Get()
		if err != nil {
			pi.log.WithError(err).Error("unable to allocate interface for host")
			return nil, nil, err
		}
	} else {
		res = &pool.Resource{
			InterfaceInfo: hostInterface,
			InUse:         true,
		}
	}

	link, err := linkByName(res.InterfaceInfo.InterfaceName)
	if err != nil {
		pi.log.WithError(err).Error("Error getting host interface")
		return nil, nil, err
	}
	// delete any set address on interface
	ips, err := addrList(link, netlink.FAMILY_V4)
	if err != nil {
		pi.log.WithError(err).Error("Failed to list IPs on interface")
		return nil, nil, err
	}
	for _, ip := range ips {
		if err := addrDel(link, &ip); err != nil {
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

	if err := doSriovNetworkFunc(in, res.InterfaceInfo); err != nil {
		// if error occured after interface was already moved into containers netns move it back
		if _, ok := err.(nsError); ok {
			if err := movePodInterfaceToHostNetnsFunc(in.Netns, in.InterfaceName, res.InterfaceInfo); err != nil {
				pi.log.WithError(err).Error("failed to move pod interface to host network namespace")
				return nil, err
			}
		}
		pi.log.WithError(err).Error("failed to push interface to container")
		pi.pool.Release(res.InterfaceInfo.InterfaceName) // if we failed to setup the allocated interfrace then release it
		return nil, err
	}
	pi.log.Infof("Host interface name: %s interface mac %s", res.InterfaceInfo.InterfaceName, res.InterfaceInfo.MacAddr)

	refid := filepath.Base(in.Netns)
	if err = saveInterfaceConf(utilsGetDataDirPath(types.SriovPodInterface), refid, in.InterfaceName, res.InterfaceInfo); err != nil {
		pi.log.WithError(err).Error("storing cache failed")
		return nil, err
	}
	return res.InterfaceInfo, nil
}

func (pi *sriovPodInterface) ReleasePodInterface(in *pb.DelRequest) error {
	// release used VF
	dataDir := utilsGetDataDirPath(types.SriovPodInterface)
	refid := filepath.Base(in.Netns)
	conf, err := readInterfaceConf(dataDir, refid, in.InterfaceName)
	if err != nil {
		return err
	}
	if err := movePodInterfaceToHostNetnsFunc(in.Netns, in.InterfaceName, conf); err != nil {
		return err
	}
	pi.pool.Release(conf.InterfaceName)
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
	conf, err := readInterfaceConf(utilsGetDataDirPath(types.SriovPodInterface), refid, in.InterfaceName)
	if err != nil {
		out.Successful = false
		out.ErrorMessage = err.Error()
		return out, err
	}
	var ip string = ""
	// fetch interface IP
	err = withNetNSPath(in.Netns, func(_ ns.NetNS) error {
		linkObj, err := linkByName(in.InterfaceName)
		if err != nil {
			pi.log.WithError(err).Errorf("failed to find netlink device with name %s", in.InterfaceName)
			return err
		}
		l, err := addrList(linkObj, netlink.FAMILY_V4)
		if err != nil || len(l) == 0 {
			pi.log.WithError(err).Error("Failed to fetch IP address from Pod interface or IP not set")
			return err
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
