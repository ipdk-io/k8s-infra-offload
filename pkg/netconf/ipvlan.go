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
	"fmt"

	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/utils/sysctl"
	"github.com/ipdk-io/k8s-infra-offload/pkg/types"
	pb "github.com/ipdk-io/k8s-infra-offload/proto"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

var (
	linkAdd       = netlink.LinkAdd
	sysctlFunc    = sysctl.Sysctl
	delLinkByName = ip.DelLinkByName
)

func DoIpvlanNetwork(in *pb.AddRequest, master string, mode netlink.IPVlanMode) (string, error) {
	logger := log.WithField("func", "DoIpvlanNetwork").WithField("pkg", "netconf")
	m, err := linkByName(master)
	if err != nil {
		logger.WithError(err).Error("Cannot get master interface")
		return "", err
	}

	netns, err := getNS(in.GetNetns())
	if err != nil {
		logger.WithError(err).Error("Failed to get network namespace")
		return "", err
	}

	mv := &netlink.IPVlan{
		LinkAttrs: netlink.LinkAttrs{
			MTU:         int(in.GetSettings().GetMtu()),
			Name:        in.DesiredHostInterfaceName,
			ParentIndex: m.Attrs().Index,
			Namespace:   netlink.NsFd(int(netns.Fd())),
		},
		Mode: mode,
	}

	if err := linkAdd(mv); err != nil {
		logger.WithError(err).Error("Failed to create ipvlan")
		return "", fmt.Errorf("failed to create ipvlan to %s %v", master, err)
	}

	ipList, contMac, err := configureIpvlanNamespace(netns, mv, in)

	if err != nil {
		return "", err
	}
	// setup routing via infra_host for pod IP address
	if len(ipList) > 0 {
		if err = setupRouting(ipList); err != nil {
			return "", err
		}
	}

	return contMac, nil
}

func setupRouting(ipList []netlink.Addr) error {
	logger := log.WithField("func", "setupRouting").WithField("pkg", "netconf")
	infraHostLink, err := linkByName(types.InfraHost)
	if err != nil {
		logger.WithError(err).Error("Cannot get Infra host interface")
		return err
	}
	gw, err := netlink.ParseAddr(types.DefaultRoute)
	if err != nil {
		return fmt.Errorf("Failed to pasre DefaultRoute GW addr %s: %w", types.DefaultRoute, err)
	}
	if err := setupHostRoute(ipList[0].IPNet, gw.IPNet, infraHostLink); err != nil {
		return err
	}
	return nil
}

func configureIpvlanNamespace(netns ns.NetNS, mv *netlink.IPVlan, in *pb.AddRequest) ([]netlink.Addr, string, error) {
	var ipList []netlink.Addr
	var contMac string = ""
	err := netns.Do(func(_ ns.NetNS) error {
		if err := linkSetName(mv, in.InterfaceName); err != nil {
			return fmt.Errorf("failed to rename interface: %w", err)
		}
		// re-fetch ipvlan
		contIpvlan, err := linkByName(in.InterfaceName)
		if err != nil {
			return fmt.Errorf("failed to refetch ipvlan %q: %w", in.InterfaceName, err)
		}
		_, _ = sysctlFunc(fmt.Sprintf("net/ipv4/conf/%s/arp_notify", in.InterfaceName), "1")
		if err = setLinkAddress(contIpvlan, in.GetContainerIps()); err != nil {
			return fmt.Errorf("failed to set link address: %w", err)
		}
		if err = linkSetUp(contIpvlan); err != nil {
			return err
		}
		if err = setupPodRoute(contIpvlan, in.ContainerRoutes, nonTargetIP); err != nil {
			return fmt.Errorf("cannot setup routes: %w", err)
		}
		contMac = contIpvlan.Attrs().HardwareAddr.String()
		ipList, err = addrList(contIpvlan, netlink.FAMILY_V4)
		if err != nil {
			return err
		}

		return nil
	})
	return ipList, contMac, err
}

func ReleaseIpvlanNetwork(in *pb.DelRequest) error {
	var podIp netlink.Addr
	err := withNetNSPath(in.GetNetns(), func(_ ns.NetNS) error {
		// don't return an error if the device is already removed
		link, err := linkByName(in.GetInterfaceName())
		if err == nil {
			al, err := addrList(link, netlink.FAMILY_V4)
			if err == nil || len(al) > 0 {
				podIp = al[0]
			}
		}
		if err := delLinkByName(in.GetInterfaceName()); err != nil {
			if err != ip.ErrLinkNotFound {
				return err
			}
		}
		return nil
	})
	// delete route on host
	if podIp.IPNet != nil {
		infraHost, err := linkByName(types.InfraHost)
		if err == nil {
			// ignore errors
			_ = routeDel(&netlink.Route{LinkIndex: infraHost.Attrs().Index, Dst: podIp.IPNet, Scope: netlink.SCOPE_LINK})
		}
	}

	if err != nil {
		_, ok := err.(ns.NSPathNotExistErr)
		if ok {
			return nil
		}
		return err
	}
	return nil
}
