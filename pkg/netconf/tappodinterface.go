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

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/ipdk-io/k8s-infra-offload/pkg/pool"
	"github.com/ipdk-io/k8s-infra-offload/pkg/types"
	"github.com/ipdk-io/k8s-infra-offload/pkg/utils"
	pb "github.com/ipdk-io/k8s-infra-offload/proto"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/vishvananda/netlink"
)

var (
	getTapInterfaces               = utils.GetTapInterfaces
	configureHostInterfaceFunc     = configureHostInterface
	setHostInterfaceInPodNetnsFunc = setHostInterfaceInPodNetns
)

type tapPodInterface struct {
	log  *logrus.Entry
	pool pool.ResourcePool
}

func NewTapPodInterface(log *logrus.Entry) (types.PodInterface, error) {
	pi := &tapPodInterface{log: log}
	intfs, err := pi.configurePool()
	if err != nil {
		log.WithError(err).Error("failed to configure pool")
		return nil, err
	}
	if err := pi.setup(intfs); err != nil {
		log.WithError(err).Error("failed to setup tap interface")
		return nil, err
	}
	return pi, nil
}

func (pi *tapPodInterface) configurePool() ([]*types.InterfaceInfo, error) {
	tapPrefix := viper.GetString("tapPrefix")
	pi.log.Infof("Scanning for Host Tap for interfaces using prefix %s", tapPrefix)
	intfs, err := getTapInterfaces(tapPrefix)
	if err != nil {
		pi.log.Error("empty resource pool, Pod network interface will not be configured")
		return nil, err
	}
	pi.log.Infof("Found %v of host Tap interfaces", len(intfs))
	if len(intfs) == 0 {
		return nil, fmt.Errorf("failed to discover host Tap interfaces with prefix %s", tapPrefix)
	}

	pi.log.Infof("Interface list:")
	for _, intf := range intfs {
		pi.log.Infof("Interface Name: %s Mac: %s", intf.InterfaceName, intf.MacAddr)
	}

	pool := pool.NewResourcePool(intfs, utilsGetDataDirPath(types.TapInterface))
	pi.pool = pool
	return intfs, nil
}

func (pi *tapPodInterface) setup(intfs []*types.InterfaceInfo) error {
	var res *pool.Resource
	// check if we have config in cache
	hostInterface, err := readInterfaceConf(utilsGetDataDirPath(types.TapInterface), types.HostInterfaceRefId, types.HostInterfaceRefId)
	if err != nil {
		// get one interface for host networking and assign first address
		res, err = pi.pool.Get()
		if err != nil {
			pi.log.WithError(err).Error("unable to allocate interface for host")
			return err
		}
	} else {
		res = &pool.Resource{
			InterfaceInfo: hostInterface,
			InUse:         true,
		}
	}

	_, ipnet, err := net.ParseCIDR(types.HostInterfaceAddr)

	if err != nil {
		pi.log.WithError(err).Error("Failed to get IP for host interface")
		return err
	}
	pi.log.Printf("Host IP address: %s", ipnet)

	if err := configureHostInterfaceFunc(res.InterfaceInfo.InterfaceName, ipnet, intfs, pi.log); err != nil {
		return fmt.Errorf("Failed to configure host interface %s with IP configurations: %w", res.InterfaceInfo.InterfaceName, err)
	}
	// set host interface name
	types.NodeInfraHostInterfaceName = res.InterfaceInfo.InterfaceName

	// dial inframanager and setup host interface
	request := &pb.SetupHostInterfaceRequest{
		IfName:   types.NodeInfraHostInterfaceName,
		Ipv4Addr: ipnet.String(),
		MacAddr:  res.InterfaceInfo.MacAddr,
	}
	if err := sendSetupHostInterfaceFunc(request); err != nil {
		return err
	}
	// save host interface setting in cache
	if err := saveInterfaceConf(utilsGetDataDirPath(types.TapInterface), types.HostInterfaceRefId, types.HostInterfaceRefId, res.InterfaceInfo); err != nil {
		return err
	}
	return nil
}

func configureHostInterface(ifName string, ipnet *net.IPNet, interfaces []*types.InterfaceInfo, log *logrus.Entry) error {

	link, err := linkByName(ifName)
	if err != nil {
		log.WithError(err).Errorf("error getting netlink object with inteface name: %s", ifName)
		return err
	}
	// delete any set address on interface
	ips, err := addrList(link, netlink.FAMILY_V4)
	if err != nil {
		log.WithError(err).Error("Failed to list IPs on interface")
		return err
	}
	for _, ip := range ips {
		if err := addrDel(link, &ip); err != nil {
			log.WithError(err).Error("Failed to remove ip address")
		}
	}

	if err := addrAdd(link, &netlink.Addr{IPNet: ipnet}); err != nil {
		log.WithError(err).Error("Failed to set ip address for interface")
		return err
	}

	if err := linkSetMTU(link, types.HostInterfaceMTU); err != nil {
		log.WithError(err).Errorf("Failed to set MTU %v for host interface", types.HostInterfaceMTU)
		return err
	}
	log.Infof("Host interface MTU is set: %v", types.HostInterfaceMTU)

	if err := linkSetUp(link); err != nil {
		log.WithError(err).Error("Failed to set interface up")
		return err
	}
	// setup routing from pods CIDR via host side tap interface
	// check if it exist already
	if err := configureRoutingFunc(link, log); err != nil {
		log.WithError(err).Error("Failed to configure routing")
		return err
	}
	return nil
}

func (pi *tapPodInterface) CreatePodInterface(in *pb.AddRequest) (*types.InterfaceInfo, error) {
	res, err := pi.pool.Get()
	if err != nil {
		pi.log.Errorf("failed to get a free interface for pod error: %v", err)
		return nil, err
	}
	pi.log.Infof("Interface allocated for Pod: %s", res.InterfaceInfo.InterfaceName)

	if err := setHostInterfaceInPodNetnsFunc(in, res.InterfaceInfo); err != nil {
		if _, ok := err.(nsError); ok {
			_ = movePodInterfaceToHostNetnsFunc(in.Netns, in.InterfaceName, res.InterfaceInfo)
		}
		pi.log.WithError(err).Error("failed to push interface to container")
		pi.pool.Release(res.InterfaceInfo.InterfaceName) // if we failed to setup the allocated interface then release it
		return nil, err
	}
	pi.log.Infof("Host interface name: %s interface mac %s", res.InterfaceInfo.InterfaceName, res.InterfaceInfo.MacAddr)

	refid := filepath.Base(in.Netns)
	if err = saveInterfaceConf(utilsGetDataDirPath(types.TapInterface), refid, in.InterfaceName, res.InterfaceInfo); err != nil {
		pi.log.WithError(err).Error("storing cache failed")
		return nil, err
	}
	return res.InterfaceInfo, nil
}

func (pi *tapPodInterface) ReleasePodInterface(in *pb.DelRequest) error {
	// release used interface
	refid := filepath.Base(in.Netns)
	conf, err := readInterfaceConf(utilsGetDataDirPath(types.TapInterface), refid, in.InterfaceName)
	if err != nil {
		if os.IsNotExist(err) {
			pi.log.WithError(err).Infof("interface config cache file for refid %s is not found", refid)
			return nil // If cache file does not exist, then most like pod interface was not created by agent or may have been deleted. Nothing else to do for us
		}
		return err
	}
	if err := movePodInterfaceToHostNetnsFunc(in.Netns, in.InterfaceName, conf); err != nil {
		return err
	}
	pi.pool.Release(conf.InterfaceName)
	// remove cache, ignore error
	path := filepath.Join(utilsGetDataDirPath(types.TapInterface), refid+"-"+in.InterfaceName)
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
	conf, err := readInterfaceConf(utilsGetDataDirPath(types.TapInterface), refid, in.InterfaceName)
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
