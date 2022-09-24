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

	"github.com/ipdk-io/k8s-infra-offload/pkg/types"
	pb "github.com/ipdk-io/k8s-infra-offload/proto"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

type ipvlanPodInterface struct {
	log    *logrus.Entry
	master string
	podMac string
	mode   netlink.IPVlanMode
}

func NewIpvlanPodInterface(log *logrus.Entry) (types.PodInterface, error) {
	return &ipvlanPodInterface{log: log, master: types.NodeInterfaceName, mode: netlink.IPVLAN_MODE_L3}, nil
}

func (p *ipvlanPodInterface) CreatePodInterface(in *pb.AddRequest) (*types.InterfaceInfo, error) {

	contMac, err := DoIpvlanNetwork(in, p.master, p.mode)
	if err != nil {
		p.log.WithError(err).Error("failed to configure network interface")
		return nil, err
	}
	p.podMac = contMac
	p.log.Infof("host interface name %s mac %s", p.master, p.podMac)
	intfInfo := &types.InterfaceInfo{MacAddr: contMac, InterfaceName: p.master}
	return intfInfo, nil
}

func (p *ipvlanPodInterface) ReleasePodInterface(in *pb.DelRequest) error {
	return ReleaseIpvlanNetwork(in)
}

func (p *ipvlanPodInterface) SetupNetwork(ctx context.Context, c pb.InfraAgentClient, intfInfo *types.InterfaceInfo, in *pb.AddRequest) (*pb.AddReply, error) {
	request := &pb.CreateNetworkRequest{
		AddRequest: in,
		HostIfName: in.DesiredHostInterfaceName,
	}

	// Note: We may need to call different InfraAgentClient method for IPVLAN with different payloads
	out, err := c.CreateNetwork(ctx, request)
	if err != nil {
		return nil, err
	}

	return out, nil
}

func (p *ipvlanPodInterface) ReleaseNetwork(ctx context.Context, c pb.InfraAgentClient, in *pb.DelRequest) (*pb.DelReply, error) {
	// Stub implementation
	return nil, nil
}
