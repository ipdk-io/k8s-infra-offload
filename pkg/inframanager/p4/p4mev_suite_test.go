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

//go:build mev

package p4_test

import (
	"context"
	"github.com/antoninbas/p4runtime-go-client/pkg/client"
	p4 "github.com/ipdk-io/k8s-infra-offload/pkg/inframanager/p4"
	"github.com/ipdk-io/k8s-infra-offload/pkg/inframanager/store"
	p4_v1 "github.com/p4lang/p4runtime/go/p4/v1"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var (
	errorcase = false
)

func TestP4(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "P4 Suite")
}

var _ = Describe("cni", func() {

	var deviceID uint64
	var electionID p4_v1.Uint128
	var p4RtC *client.Client
	ctx := context.Background()
	c := p4_v1.NewP4RuntimeClient(nil)
	deviceID = 1
	electionID = p4_v1.Uint128{High: 0, Low: 1}
	p4RtC = client.NewClient(c, deviceID, &electionID)

	Describe("ArptToPortTable", func() {

		Context("Programs ArptToPortTable", func() {

			BeforeEach(func() {
				p4.Env = "test"
				p4.Errorcase = false
				store.NewService()
			})

			ep := store.EndPoint{
				InterfaceID:  1,
				PodIpAddress: "10.10.10.1",
			}

			It("returns nil if insert to table is success", func() {
				ret := p4.ArptToPortTable(ctx, p4RtC, ep.PodIpAddress, ep.InterfaceID, true)
				Expect(ret).Should(BeNil())
			})

			It("returns err if insert to table fails", func() {
				p4.Errorcase = true
				err := p4.ArptToPortTable(ctx, p4RtC, ep.PodIpAddress, ep.InterfaceID, true)
				Expect(err).To(HaveOccurred())
			})

			It("returns nil if delete from table is success", func() {
				ret := p4.ArptToPortTable(ctx, p4RtC, ep.PodIpAddress, ep.InterfaceID, false)
				Expect(ret).Should(BeNil())
			})

			It("returns err if delete from table fails", func() {
				p4.Errorcase = true
				err := p4.ArptToPortTable(ctx, p4RtC, ep.PodIpAddress, ep.InterfaceID, false)
				Expect(err).To(HaveOccurred())
			})

		})

	})

	Describe("GWMacModTable", func() {

		Context("Programs GWMacModTable", func() {

			BeforeEach(func() {
				p4.Env = "test"
				p4.Errorcase = false
				store.NewService()
			})

			ep := store.EndPoint{
				ModPtr:        1,
				InterfaceID:   1,
				PodIpAddress:  "10.10.10.1",
				PodMacAddress: "00:00:00:aa:aa:aa",
			}

			It("returns nil if insert to table is success", func() {
				ret := p4.GWMacModTable(ctx, p4RtC, ep.PodIpAddress, uint16(ep.InterfaceID), ep.PodMacAddress, ep.ModPtr, true)
				Expect(ret).Should(BeNil())
			})

			It("returns err if insert to table fails", func() {
				p4.Errorcase = true
				err := p4.GWMacModTable(ctx, p4RtC, ep.PodIpAddress, uint16(ep.InterfaceID), ep.PodMacAddress, ep.ModPtr, true)
				Expect(err).To(HaveOccurred())
			})

			It("returns nil if delete from table is success", func() {
				ret := p4.GWMacModTable(ctx, p4RtC, ep.PodIpAddress, uint16(ep.InterfaceID), ep.PodMacAddress, ep.ModPtr, false)
				Expect(ret).Should(BeNil())
			})

			It("returns err if delete from table fails", func() {
				p4.Errorcase = true
				err := p4.GWMacModTable(ctx, p4RtC, ep.PodIpAddress, uint16(ep.InterfaceID), ep.PodMacAddress, ep.ModPtr, false)
				Expect(err).To(HaveOccurred())
			})

		})

	})

	Describe("Ipv4ToPortTable", func() {

		Context("Programs Ipv4ToPortTable", func() {

			BeforeEach(func() {
				p4.Env = "test"
				p4.Errorcase = false
				store.NewService()
			})

			ep := store.EndPoint{
				ModPtr:        1,
				InterfaceID:   1,
				PodIpAddress:  "10.10.10.1",
				PodMacAddress: "00:00:00:aa:aa:aa",
			}

			It("returns nil if insert to table is success", func() {
				ret := p4.Ipv4ToPortTable(ctx, p4RtC, ep.PodIpAddress, ep.InterfaceID, ep.ModPtr, true)
				Expect(ret).Should(BeNil())
			})

			It("returns err if insert to table fails", func() {
				p4.Errorcase = true
				err := p4.Ipv4ToPortTable(ctx, p4RtC, ep.PodIpAddress, ep.InterfaceID, ep.ModPtr, true)
				Expect(err).To(HaveOccurred())
			})

			It("returns nil if delete from table is success", func() {
				ret := p4.Ipv4ToPortTable(ctx, p4RtC, ep.PodIpAddress, ep.InterfaceID, ep.ModPtr, false)
				Expect(ret).Should(BeNil())
			})

			It("returns err if delete from table fails", func() {
				p4.Errorcase = true
				err := p4.Ipv4ToPortTable(ctx, p4RtC, ep.PodIpAddress, ep.InterfaceID, ep.ModPtr, false)
				Expect(err).To(HaveOccurred())
			})

		})

	})

	Describe("InsertCniRules", func() {

		Context("Programs cni rules", func() {
			store.NewEndPoint()
			It("returns error if IP is invalid", func() {
				ep := store.EndPoint{
					ModPtr:        1,
					InterfaceID:   1,
					PodIpAddress:  "a.b.c.d",
					PodMacAddress: "00:00:00:aa:aa:aa",
				}
				_, err := p4.InsertCniRules(ctx, p4RtC, ep, 1)
				Expect(err).To(HaveOccurred())
			})

			It("returns error if MAC is invalid", func() {
				ep := store.EndPoint{
					ModPtr:        2,
					InterfaceID:   1,
					PodIpAddress:  "10.10.10.1",
					PodMacAddress: "z.z.z.z.z",
				}
				_, err := p4.InsertCniRules(ctx, p4RtC, ep, 1)
				Expect(err).To(HaveOccurred())
			})

		})

	})

	Describe("DeleteCniRules", func() {

		Context("Deletes cni rules", func() {
			store.NewEndPoint()
			It("returns error if IP is invalid", func() {
				ep := store.EndPoint{
					ModPtr:        1,
					InterfaceID:   1,
					PodIpAddress:  "a.b.c.d",
					PodMacAddress: "00:00:00:aa:aa:aa",
				}
				err := p4.DeleteCniRules(ctx, p4RtC, ep)
				Expect(err).To(HaveOccurred())
			})

		})

	})

})
