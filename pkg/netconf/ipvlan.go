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

func DoIpvlanNetwork(in *pb.AddRequest, master string, mode netlink.IPVlanMode) (string, error) {
	logger := log.WithField("func", "DoIpvlanNetwork").WithField("pkg", "netconf")
	m, err := netlink.LinkByName(master)
	if err != nil {
		logger.WithError(err).Error("Cannot get master interface")
		return "", err
	}

	netns, err := ns.GetNS(in.GetNetns())
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

	if err := netlink.LinkAdd(mv); err != nil {
		logger.WithError(err).Error("Failed to create ipvlan")
		return "", fmt.Errorf("failed to create ipvlan to %s %v", master, err)
	}

	ipList, contMac, err := configureIpvlanNamespace(netns, mv, in)

	if err != nil {
		return "", err
	}
	// setup routing via infra_host for pod IP address
	if len(ipList) > 0 {
		infraHostLink, err := netlink.LinkByName(types.InfraHost)
		if err != nil {
			logger.WithError(err).Error("Cannot get Infra host interface")
			return "", err
		}
		if err := setupHostRoute(ipList[0].IPNet, infraHostLink); err != nil {
			return "", err
		}
	}

	return contMac, nil
}

func configureIpvlanNamespace(netns ns.NetNS, mv *netlink.IPVlan, in *pb.AddRequest) ([]netlink.Addr, string, error) {
	var ipList []netlink.Addr
	var contMac string = ""
	err := netns.Do(func(_ ns.NetNS) error {
		if err := netlink.LinkSetName(mv, in.InterfaceName); err != nil {
			return fmt.Errorf("failed to rename interface: %w", err)
		}
		// re-fetch ipvlan
		contIpvlan, err := netlink.LinkByName(in.InterfaceName)
		if err != nil {
			return fmt.Errorf("failed to refetch ipvlan %q: %w", in.InterfaceName, err)
		}
		_, _ = sysctl.Sysctl(fmt.Sprintf("net/ipv4/conf/%s/arp_notify", in.InterfaceName), "1")
		if err = setLinkAddress(contIpvlan, in.GetContainerIps()); err != nil {
			return fmt.Errorf("failed to set link address: %w", err)
		}
		if err = netlink.LinkSetUp(contIpvlan); err != nil {
			return err
		}
		if err = setupPodRoute(contIpvlan, in.ContainerRoutes); err != nil {
			return fmt.Errorf("cannot setup routes: %w", err)
		}
		contMac = contIpvlan.Attrs().HardwareAddr.String()
		ipList, err = netlink.AddrList(contIpvlan, netlink.FAMILY_V4)
		if err != nil {
			return err
		}

		return nil
	})
	return ipList, contMac, err
}

func ReleaseIpvlanNetwork(in *pb.DelRequest) error {
	var podIp netlink.Addr
	err := ns.WithNetNSPath(in.GetNetns(), func(_ ns.NetNS) error {
		// don't return an error if the device is already removed
		link, err := netlink.LinkByName(in.GetInterfaceName())
		if err == nil {
			al, err := netlink.AddrList(link, netlink.FAMILY_V4)
			if err == nil || len(al) > 0 {
				podIp = al[0]
			}
		}
		if err := ip.DelLinkByName(in.GetInterfaceName()); err != nil {
			if err != ip.ErrLinkNotFound {
				return err
			}
		}
		return nil
	})
	// delete route on host
	if podIp.IPNet != nil {
		infraHost, err := netlink.LinkByName(types.InfraHost)
		if err == nil {
			// ignore errors
			_ = netlink.RouteDel(&netlink.Route{LinkIndex: infraHost.Attrs().Index, Dst: podIp.IPNet, Scope: netlink.SCOPE_LINK})
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
