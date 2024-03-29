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

//go:build es2k

package test

import (
	"context"
	"testing"

	"github.com/antoninbas/p4runtime-go-client/pkg/client"
	p4 "github.com/ipdk-io/k8s-infra-offload/pkg/inframanager/p4"
	"github.com/ipdk-io/k8s-infra-offload/pkg/inframanager/store"
	p4_v1 "github.com/p4lang/p4runtime/go/p4/v1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var (
	tempDir   string
	idgentest *p4.IdGenerator
)
var (
	errorcase = false
)

func TestP4Services(t *testing.T) {
	p4.Env = "test"
	p4.Errorcase = false
	RegisterFailHandler(Fail)
	RunSpecs(t, "P4 Suite")
}

var _ = Describe("service", func() {

	var deviceID uint64
	var electionID p4_v1.Uint128
	var p4RtC *client.Client
	ctx := context.Background()
	c := p4_v1.NewP4RuntimeClient(nil)
	deviceID = 1
	electionID = p4_v1.Uint128{High: 0, Low: 1}
	p4RtC = client.NewClient(c, deviceID, &electionID)
	var podIpAddr = []string{"10.10.10.1", "10.10.10.2"}
	var portID = []uint16{1, 2}
	idgentest = p4.NewIdGenerator(0, 0)
	store.NewSetup()

	Describe("DeleteServiceRules", func() {

		Context("deletes service rules invalid entry", func() {

			It("returns error if entry is not found", func() {
				store.NewService()
				service := store.Service{
					ClusterIp: "10.100.1.1",
					Port:      10000,
					Proto:     "TCP",
					GroupID:   1,
				}
				err := p4.DeleteServiceRules(ctx, p4RtC, service)
				Expect(err).To(HaveOccurred())
			})

		})

	})

	Describe("DeleteServiceRules", func() {

		Context("deletes service rule valid entry", func() {

			It("returns success if entry is found", func() {
				store.NewEndPoint()
				data_valid := store.EndPoint{
					ModPtr:        1,
					PodIpAddress:  "10.10.10.1",
					InterfaceID:   1,
					PodMacAddress: "00:00:00:aa:aa:aa",
				}
				data_valid.WriteToStore()
				data_valid = store.EndPoint{
					ModPtr:        2,
					PodIpAddress:  "10.10.10.2",
					InterfaceID:   1,
					PodMacAddress: "00:00:00:aa:aa:aa",
				}
				data_valid.WriteToStore()
				default_route := store.EndPoint{
					ModPtr:        3,
					PodIpAddress:  "169.254.1.1",
					InterfaceID:   1,
					PodMacAddress: "00:00:00:aa:aa:aa",
				}
				default_route.WriteToStore()

				store.NewService()
				ep1 := store.ServiceEndPoint{
					IpAddress: "10.10.10.1",
					Port:      8081,
					MemberID:  1,
				}
				ep2 := store.ServiceEndPoint{
					IpAddress: "10.10.10.2",
					Port:      8082,
					MemberID:  2,
				}
				service := store.Service{
					ClusterIp:       "10.100.1.1",
					Port:            10000,
					Proto:           "TCP",
					ServiceEndPoint: make(map[string]store.ServiceEndPoint),
				}
				service.ServiceEndPoint["10.10.10.1"] = ep1
				service.ServiceEndPoint["10.10.10.2"] = ep2
				ret := service.WriteToStore()
				Expect(ret).To(Equal(true))

				err, _ := p4.InsertServiceRules(ctx, p4RtC, podIpAddr, portID, service, idgentest, false)
				Expect(err).ShouldNot(HaveOccurred())

				err = p4.DeleteServiceRules(ctx, p4RtC, service)
				Expect(err).ShouldNot(HaveOccurred())
			})

		})

	})

	Describe("InsertServiceRules", func() {

		Context("inserts service rules", func() {

			It("inserts a valid entry", func() {
				store.NewEndPoint()
				data_valid := store.EndPoint{
					ModPtr:        1,
					PodIpAddress:  "10.10.10.1",
					InterfaceID:   1,
					PodMacAddress: "00:00:00:aa:aa:aa",
				}
				data_valid.WriteToStore()
				data_valid = store.EndPoint{
					ModPtr:        2,
					PodIpAddress:  "10.10.10.2",
					InterfaceID:   1,
					PodMacAddress: "00:00:00:aa:aa:aa",
				}
				data_valid.WriteToStore()
				default_route := store.EndPoint{
					ModPtr:        3,
					PodIpAddress:  "169.254.1.1",
					InterfaceID:   1,
					PodMacAddress: "00:00:00:aa:aa:aa",
				}
				default_route.WriteToStore()

				store.NewService()
				ep1 := store.ServiceEndPoint{
					IpAddress: "10.10.10.1",
					Port:      8081,
					MemberID:  1,
				}
				ep2 := store.ServiceEndPoint{
					IpAddress: "10.10.10.2",
					Port:      8082,
					MemberID:  2,
				}
				service := store.Service{
					ClusterIp:       "10.100.1.1",
					Port:            10000,
					Proto:           "TCP",
					ServiceEndPoint: make(map[string]store.ServiceEndPoint),
				}
				service.ServiceEndPoint["10.10.10.1"] = ep1
				service.ServiceEndPoint["10.10.10.2"] = ep2
				ret := service.WriteToStore()
				Expect(ret).To(Equal(true))

				err, _ := p4.InsertServiceRules(ctx, p4RtC, podIpAddr, portID, service, idgentest, false)
				Expect(err).ShouldNot(HaveOccurred())
			})

		})
	})

	Describe("InsertServiceRules", func() {

		Context("inserts service rules", func() {

			It("returns error if IP is invalid", func() {
				store.NewService()
				service := store.Service{
					ClusterIp: "10.100.a.1",
					Port:      10000,
					Proto:     "TCP",
				}
				err, _ := p4.InsertServiceRules(ctx, p4RtC, podIpAddr, portID, service, idgentest, false)
				Expect(err).To(HaveOccurred())
			})

		})

	})

})
