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

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/ipdk-io/k8s-infra-offload/pkg/types"
	pb "github.com/ipdk-io/k8s-infra-offload/proto"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

var (
	setLinkAddressFunc = setLinkAddress
)

func setHostInterfaceInPodNetns(in *pb.AddRequest, res *types.InterfaceInfo) error {
	logger := log.WithField("func", "setHostInterfaceInPodNetns").WithField("pkg", "netconf")
	logger.Infof("Configuring pod interface %s for Pod network", res.InterfaceName)
	nn, err := getNS(in.GetNetns())
	if err != nil {
		logger.WithError(err).Errorf("cannot find network namespace %s", in.GetNetns())
		return err
	}

	linkObj, err := linkByName(res.InterfaceName)
	if err != nil {
		return err
	}

	if err = linkSetDown(linkObj); err != nil {
		return err
	}

	if in.GetSettings().Mtu > 0 {
		if err = linkSetMTU(linkObj, int(in.GetSettings().Mtu)); err != nil {
			logger.WithError(err).Errorf("not able to set MTU %v", in.GetSettings())
			return err
		}
	}

	if err = linkSetNsFd(linkObj, int(nn.Fd())); err != nil {
		logger.WithError(err).Error("Cannot move to given namespace")
		return err
	}
	if err = configureTapNamespace(in, linkObj); err != nil {
		return newNsError(err)
	}
	return nil
}

func configureTapNamespace(in *pb.AddRequest, linkObj netlink.Link) error {
	return withNetNSPath(in.Netns, func(nn ns.NetNS) error {
		if err := linkSetName(linkObj, in.InterfaceName); err != nil {
			return fmt.Errorf("Cannot set link name: %w", err)

		}
		// re-fetch link information
		linkObj, err := linkByName(in.InterfaceName)
		if err != nil {
			return err
		}

		if err = linkSetUp(linkObj); err != nil {
			return fmt.Errorf("Cannot set link up: %w", err)
		}

		if err := setupGwRoute(linkObj, types.DefaultRoute); err != nil {
			return fmt.Errorf("Cannot setup routes: %w", err)
		}

		if err := setupPodRoute(linkObj, in.ContainerRoutes, types.DefaultRoute); err != nil {
			return fmt.Errorf("Cannot setup routes: %w", err)
		}

		if err = setLinkAddressFunc(linkObj, in.ContainerIps); err != nil {
			return fmt.Errorf("Cannot set link address: %w", err)
		}

		return nil
	})
}
