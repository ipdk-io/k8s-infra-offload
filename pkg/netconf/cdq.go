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
	"errors"
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
	"github.com/vishvananda/netlink"
)

var (
	newCDQManagerFunc = utils.NewCDQManager
	getCDQList        = utils.GetCDQList
)

type cdqIntfHandler struct {
	log  *logrus.Entry
	pool pool.ResourcePool
}

func NewCDQInterface(log *logrus.Entry) (types.PodInterface, error) {
	pi := &cdqIntfHandler{log: log}

	if err := pi.setup(); err != nil {
		log.WithError(err).Error("failed to setup cdq interface")
		return nil, err
	}
	return pi, nil
}

func (pi *cdqIntfHandler) setup() error {

	var hostInterface *types.InterfaceInfo
	var res *pool.Resource

	if err := pi.initializePool(); err != nil {
		pi.log.WithError(err).Error("Cannot initialize cdq resource pool")
		return err
	}

	// check if we have config in cache
	hostInterface, err := readInterfaceConf(utilsGetDataDirPath(types.CDQInterface), types.HostInterfaceRefId, types.HostInterfaceRefId)
	if err != nil {
		// Create a new CDQ interface for host
		if res, err = pi.pool.Get(); err != nil {
			pi.log.WithError(err).Error("unable to allocate a CDQ interface for the host")
			return err
		}
		hostInterface = res.InterfaceInfo

	}

	_, ipnet, err := net.ParseCIDR(types.HostInterfaceAddr)

	if err != nil {
		pi.log.WithError(err).Error("Failed to get IP for host interface")
		return err
	}
	pi.log.Infof("Host IP address: %s", ipnet)

	if err := configureHostInterfaceFunc(hostInterface.InterfaceName, ipnet, pi.log); err != nil {
		return fmt.Errorf("failed to configure host interface %s with IP configurations: %w", hostInterface.InterfaceName, err)
	}
	// set host interface name
	types.NodeInfraHostInterfaceName = hostInterface.InterfaceName

	// dial inframanager and setup host interface
	request := &pb.SetupHostInterfaceRequest{
		IfName:   types.NodeInfraHostInterfaceName,
		Ipv4Addr: ipnet.String(),
		MacAddr:  hostInterface.MacAddr,
	}
	if err := sendSetupHostInterfaceFunc(request); err != nil {
		return err
	}
	// save host interface setting in cache
	if err := saveInterfaceConf(utilsGetDataDirPath(types.CDQInterface), types.HostInterfaceRefId, types.HostInterfaceRefId, hostInterface); err != nil {
		return err
	}
	return nil
}

func (pi *cdqIntfHandler) initializePool() error {
	pi.log.Infof("Scanning for CDQ for interface %s", types.NodeInterfaceName)
	cdqs, err := getCDQList(types.NodeInterfaceName, utils.SysClassNet)
	if err != nil {
		pi.log.Error("empty resource pool, Pod network interface will not be configured")
		return err
	}
	pi.log.Infof("Found %v of CDQ(s)", len(cdqs))
	if len(cdqs) == 0 {
		return fmt.Errorf("failed to discover VF on interface %s", types.NodeInterfaceName)
	}
	pool := pool.NewResourcePool(cdqs, utilsGetDataDirPath(types.CDQInterface))
	pi.pool = pool
	return nil
}

func (pi *cdqIntfHandler) CreatePodInterface(in *pb.AddRequest) (*types.InterfaceInfo, error) {
	if in.InterfaceName == "" {
		pi.log.Errorf("Empty interfaceName")
		return nil, errors.New("Empty input request")
	}

	res, err := pi.pool.Get()
	if err != nil {
		pi.log.Errorf("failed to get a CDQ interface for pod: %v", err)
		return nil, err
	}
	intfInfo := res.InterfaceInfo

	pi.log.Infof("a new CDQ Interface allocated for Pod: %s", intfInfo.InterfaceName)

	if err := moveIntfToPodNetnsFunc(in, intfInfo); err != nil {
		if _, ok := err.(nsError); ok {
			if err := movePodInterfaceToHostNetnsFunc(in.Netns, in.InterfaceName, intfInfo); err != nil {
				pi.log.WithError(err).Error("failed to move pod interface to host network namespace")
				return nil, err
			}
		}
		pi.log.WithError(err).Error("failed to move interface to Pod")
		pi.pool.Release(intfInfo.InterfaceName) // if we failed to setup the allocated interfrace then release it
		return nil, err
	}
	pi.log.Infof("Host interface name: %s interface mac %s", intfInfo.InterfaceName, intfInfo.MacAddr)

	refid := filepath.Base(in.Netns)
	if err = saveInterfaceConf(utilsGetDataDirPath(types.CDQInterface), refid, in.InterfaceName, intfInfo); err != nil {
		pi.log.WithError(err).Error("storing cache failed")
		return nil, err
	}
	return intfInfo, nil
}

func (pi *cdqIntfHandler) ReleasePodInterface(in *pb.DelRequest) error {
	// release used interface
	refid := filepath.Base(in.Netns)
	conf, err := readInterfaceConf(utilsGetDataDirPath(types.CDQInterface), refid, in.InterfaceName)
	if err != nil {
		if os.IsNotExist(err) {
			pi.log.WithError(err).Infof("interface config cache file for refid %s is not found", refid)
			return nil // If cache file does not exist, then most likely pod interface was not created by agent or may have been deleted. Nothing else to do here.
		}
		return err
	}
	if err := movePodInterfaceToHostNetnsFunc(in.Netns, in.InterfaceName, conf); err != nil {
		return err
	}

	pi.pool.Release(conf.InterfaceName)
	return nil
}

func (pi *cdqIntfHandler) SetupNetwork(ctx context.Context, c pb.InfraAgentClient, intfInfo *types.InterfaceInfo, in *pb.AddRequest) (*pb.AddReply, error) {
	request := &pb.CreateNetworkRequest{
		AddRequest: in,
		HostIfName: in.DesiredHostInterfaceName,
		MacAddr:    intfInfo.MacAddr,
	}

	out, err := c.CreateNetwork(ctx, request)
	if err != nil {
		return nil, err
	}

	return out, nil
}

func (pi *cdqIntfHandler) ReleaseNetwork(ctx context.Context, c pb.InfraAgentClient, in *pb.DelRequest) (*pb.DelReply, error) {
	out := &pb.DelReply{
		Successful: true,
	}
	// get interface config from cache
	refid := filepath.Base(in.Netns)
	conf, err := readInterfaceConf(utilsGetDataDirPath(types.CDQInterface), refid, in.InterfaceName)
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
			pi.log.WithError(err).Error("failed to fetch IP address from Pod interface or IP not set")
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
