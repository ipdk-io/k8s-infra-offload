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

	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/ipdk-io/k8s-infra-offload/pkg/types"
	"github.com/ipdk-io/k8s-infra-offload/pkg/utils"
	pb "github.com/ipdk-io/k8s-infra-offload/proto"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const nonTargetIP = "0.0.0.0/0"

var (
	addrAdd                         = netlink.AddrAdd
	addrDel                         = netlink.AddrDel
	addrList                        = netlink.AddrList
	configureRoutingFunc            = configureRouting
	getCurrentNS                    = ns.GetCurrentNS
	getIPFromIPAM                   = utils.GetIPFromIPAM
	getNS                           = ns.GetNS
	grpcDial                        = grpc.Dial
	ipAddRoute                      = ip.AddRoute
	linkByName                      = netlink.LinkByName
	linkSetDown                     = netlink.LinkSetDown
	linkSetMTU                      = netlink.LinkSetMTU
	linkSetName                     = netlink.LinkSetName
	linkSetNsFd                     = netlink.LinkSetNsFd
	linkSetUp                       = netlink.LinkSetUp
	movePodInterfaceToHostNetnsFunc = movePodInterfaceToHostNetns
	newInfraAgentClient             = pb.NewInfraAgentClient
	readInterfaceConf               = utils.ReadInterfaceConf
	releaseIPFromIPAM               = utils.ReleaseIPFromIPAM
	routeAdd                        = netlink.RouteAdd
	routeDel                        = netlink.RouteDel
	routeListFiltered               = netlink.RouteListFiltered
	saveInterfaceConf               = utils.SaveInterfaceConf
	sendSetupHostInterfaceFunc      = sendSetupHostInterface
	withNetNSPath                   = ns.WithNetNSPath
	utilsGetDataDirPath             = utils.GetDataDirPath
)

type nsError struct{ msg string }

func (e nsError) Error() string { return e.msg }

func newNsError(toWrap error) nsError {
	return nsError{msg: fmt.Sprintf("Error in containers namespace: %s", toWrap.Error())}
}

func setupContainerRoutes(link netlink.Link, gw net.IP, containerRoutes []string) error {
	logger := log.WithField("func", "setupContainerRoutes").WithField("pkg", "netconf")
	for _, r := range containerRoutes {
		logger.Infof("container routes: %s", r)
		rip, err := netlink.ParseAddr(r)
		if err != nil {
			continue
		}
		rn := rip.IPNet
		if rn.IP.To4() == nil {
			logger.WithField("route", rip).Debug("Skipping non-IPv4 route")
			continue
		}
		if err = ipAddRoute(rn, gw, link); err != nil {
			return fmt.Errorf("failed to add IPv4 route for %v via %v: %v", r, gw, err)
		}
	}
	return nil
}

func setLinkAddress(link netlink.Link, containerIps []*pb.IPConfig) error {
	logger := log.WithField("func", "setLinkAddress")
	for _, e := range containerIps {
		addr, err := netlink.ParseAddr(e.GetAddress())
		if err != nil {
			continue
		}
		if addr.IP.To4() != nil {
			addr.Mask = net.CIDRMask(32, 32)
		}

		logger.Infof("Address to set %+v", addr)
		// add the IPs to the container side of the interface
		if err = addrAdd(link, &netlink.Addr{IPNet: addr.IPNet}); err != nil {
			return fmt.Errorf("failed to add IP addr to %q: %v", link, err)
		}
	}
	return nil
}

func setupPodRoute(link netlink.Link, containerRoutes []string, gateway string) error {
	// we need to setup default route via eth0
	gw, err := netlink.ParseAddr(gateway)
	if err != nil {
		return err
	}

	return setupContainerRoutes(link, gw.IP, containerRoutes)
}

func setupGwRoute(link netlink.Link, gateway string) error {
	logger := log.WithField("func", "setupGwRoute")
	gw, err := netlink.ParseAddr(gateway)
	if err != nil {
		logger.Errorf("cannot parse gateway: %s", gateway)
		return err
	}

	gwNet := &net.IPNet{IP: gw.IP, Mask: gw.Mask}
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Scope:     netlink.SCOPE_LINK,
		Dst:       gwNet,
	}

	return routeAdd(route)
}

func setupHostRoute(addr *net.IPNet, link netlink.Link) error {
	podRoute := netlink.Route{
		Dst:       addr,
		LinkIndex: link.Attrs().Index,
		Scope:     netlink.SCOPE_LINK,
	}
	log.Infof("Trying to setup %v route on Infra host interface", podRoute)

	// get routes for provided resources
	routeFilter := &netlink.Route{
		Dst: addr,
	}
	rl, err := routeListFiltered(netlink.FAMILY_V4,
		routeFilter, netlink.RT_FILTER_DST)
	if err != nil {
		return err
	}

	routeFound := false
	for _, r := range rl {
		if r.Equal(podRoute) {
			routeFound = true
			break
		} else {
			// if route exists for the CIDR, but it is not identical
			// (e.g. different interface) delete it
			log.Infof("Deleting route: %v", r)
			_ = routeDel(&r)
		}
	}

	if !routeFound {
		// route does not exist add it
		if err := routeAdd(&podRoute); err != nil {
			return err
		}
	}

	return nil
}

func configureRoutingForCIDR(link netlink.Link, cidr string, log *logrus.Entry) error {
	// get first address from Pod CIDR
	// TODO add ipv6 support
	log.Infof("CIDR %s", cidr)
	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		return err
	}

	// setup routing from pods CIDR via VF[0]
	// check if it exist already
	if err := setupHostRoute(addr.IPNet, link); err != nil {
		return fmt.Errorf("Failed to setup route to CIDR: %w", err)
	}

	return nil
}

func configureRouting(link netlink.Link, log *logrus.Entry) error {
	if err := configureRoutingForCIDR(link, types.ClusterPodsCIDR, log); err != nil {
		return fmt.Errorf("Failed to setup routing to Cluster CIDR: %w", err)
	}
	if err := configureRoutingForCIDR(link, types.NodePodsCIDR, log); err != nil {
		return fmt.Errorf("Failed to setup routing to Pods CIDR: %w", err)
	}
	if err := configureRoutingForCIDR(link, types.ClusterServicesSubnet, log); err != nil {
		return fmt.Errorf("Failed to setup routing to Service CIDR: %w", err)
	}
	return nil
}

func sendSetupHostInterface(request *pb.SetupHostInterfaceRequest) error {
	managerAddr := fmt.Sprintf("%s:%s", types.InfraManagerAddr, types.InfraManagerPort)
	conn, err := grpcDial(managerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer conn.Close()
	// defer func() {
	// 	if conn == nil {
	// 		return
	// 	}
	// 	_ = conn.Close()
	// }()
	c := newInfraAgentClient(conn)
	r, err := c.SetupHostInterface(context.TODO(), request)
	if err != nil {
		return err
	}
	if !r.Successful {
		return fmt.Errorf("failed to SetupHostInterface error %s", r.ErrorMessage)
	}
	return nil
}

func movePodInterfaceToHostNetns(netNSPath, interfaceName string, ifInfo *types.InterfaceInfo) error {
	logger := log.WithField("func", "moveInterfaceToHostNetns").WithField("pkg", "netconf")
	logger.Info("Moving Pod interface to host netns")

	rootns, err := getCurrentNS()
	if err != nil {
		logger.WithError(err).Error("cannot get current network namespace")
		return err
	}

	err = withNetNSPath(netNSPath, func(_ ns.NetNS) error {
		linkObj, err := linkByName(interfaceName)
		if err != nil {
			logger.WithError(err).Errorf("failed to find netlink device with name %s", interfaceName)
			return err
		}
		if err = linkSetDown(linkObj); err != nil {
			return err
		}
		// restore original interface name
		if err = linkSetName(linkObj, ifInfo.InterfaceName); err != nil {
			return err
		}
		return linkSetNsFd(linkObj, int(rootns.Fd()))
	})
	// namespace might be already deleted do not return error
	if err != nil {
		_, ok := err.(ns.NSPathNotExistErr)
		if ok {
			return nil
		}
		return err
	}
	return nil
}
