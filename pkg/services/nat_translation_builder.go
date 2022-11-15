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

package services

import (
	"net"

	"github.com/ipdk-io/k8s-infra-offload/pkg/types"
	"github.com/ipdk-io/k8s-infra-offload/proto"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

type NatTranslationBuilder interface {
	ForServicePort(*v1.ServicePort) NatTranslationBuilder
	WithServiceIP(serviceIP net.IP) NatTranslationBuilder
	WithIsNodePort(isNodePort bool) NatTranslationBuilder
	Build() *proto.NatTranslation
}

type natTranslationBuilder struct {
	servicePort *v1.ServicePort
	service     *v1.Service
	ep          *v1.Endpoints
	serviceIP   net.IP
	isNodePort  bool
}

func NewNatTranslationBuilder(service *v1.Service, ep *v1.Endpoints) NatTranslationBuilder {
	return &natTranslationBuilder{
		service: service,
		ep:      ep,
	}
}

func (b *natTranslationBuilder) Build() *proto.NatTranslation {
	return b.buildNatEntryForServicePort()
}

func (b *natTranslationBuilder) WithIsNodePort(isNodePort bool) NatTranslationBuilder {
	b.isNodePort = isNodePort
	return b
}

func (b *natTranslationBuilder) WithServiceIP(serviceIP net.IP) NatTranslationBuilder {
	b.serviceIP = serviceIP
	return b
}

func (b *natTranslationBuilder) ForServicePort(servicePort *v1.ServicePort) NatTranslationBuilder {
	b.servicePort = servicePort
	return b
}

func (b *natTranslationBuilder) buildNatEntryForServicePort() *proto.NatTranslation {
	backends := make([]*proto.NatEndpointTuple, 0)
	isLocal := isLocalOnly(b.service)
	if b.isNodePort {
		isLocal = false
	}
	for _, endpointSubset := range b.ep.Subsets {
		for _, endpointPort := range endpointSubset.Ports {
			if b.servicePort.Name == endpointPort.Name {
				for _, endpointAddress := range endpointSubset.Addresses {
					if !isEndpointAddressLocal(&endpointAddress) && isLocal {
						continue
					}
					// set dst addr
					backend := &proto.NatEndpointTuple{
						DstEp: &proto.NatEndpoint{
							// set port
							Port:     getDstPort(b.servicePort, &endpointPort),
							Ipv4Addr: endpointAddress.IP,
						},
					}
					if b.isNodePort {
						// add snat for nodeports
						backend.SrcEp = &proto.NatEndpoint{
							Ipv4Addr: b.serviceIP.String(),
						}
					}
					backends = append(backends, backend)
				}

			}
		}
	}
	return &proto.NatTranslation{
		Proto: string(b.servicePort.Protocol),
		Endpoint: &proto.NatEndpoint{
			// set port
			Port:     getVipDstPort(b.servicePort, b.isNodePort),
			Ipv4Addr: b.serviceIP.String(),
		},
		Backends: backends,
		IsRealIp: b.isNodePort,
	}
}

func isLocalOnly(service *v1.Service) bool {
	return service.Spec.ExternalTrafficPolicy == v1.ServiceExternalTrafficPolicyTypeLocal
}

func isEndpointAddressLocal(endpointAddress *v1.EndpointAddress) bool {
	if endpointAddress != nil && endpointAddress.NodeName != nil && *endpointAddress.NodeName != types.NodeName {
		return false
	}
	return true
}

func getDstPort(servicePort *v1.ServicePort, endpointPort *v1.EndpointPort) uint32 {
	targetPort := servicePort.TargetPort
	if targetPort.Type == intstr.Int {
		if targetPort.IntVal == 0 {
			// Unset targetport
			return uint32(servicePort.Port)
		} else {
			return uint32(targetPort.IntVal)
		}
	} else {
		return uint32(endpointPort.Port)
	}
}

func getVipDstPort(servicePort *v1.ServicePort, isNodePort bool) uint32 {
	if isNodePort {
		return uint32(servicePort.NodePort)
	}
	return uint32(servicePort.Port)
}
