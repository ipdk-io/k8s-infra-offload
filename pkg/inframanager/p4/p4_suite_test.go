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

//go:build dpdk

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
			})

			It("returns nil if insert to table is success", func() {
				ret := p4.ArptToPortTable(ctx, p4RtC, "10.10.10.1", 1, true)
				Expect(ret).Should(BeNil())
			})

			It("returns err if insert to table fails", func() {
				p4.Errorcase = true
				err := p4.ArptToPortTable(ctx, p4RtC, "10.10.10.1", 1, true)
				Expect(err).To(HaveOccurred())
			})

			It("returns nil if delete from table is success", func() {
				ret := p4.ArptToPortTable(ctx, p4RtC, "10.10.10.1", 1, false)
				Expect(ret).Should(BeNil())
			})

			It("returns err if delete from table fails", func() {
				p4.Errorcase = true
				err := p4.ArptToPortTable(ctx, p4RtC, "10.10.10.1", 1, false)
				Expect(err).To(HaveOccurred())
			})

		})

	})

	Describe("Ipv4ToPortTable", func() {

		Context("Programs Ipv4ToPortTable", func() {

			BeforeEach(func() {
				p4.Env = "test"
				p4.Errorcase = false
			})

			It("returns nil if insert to table is success", func() {
				ret := p4.Ipv4ToPortTable(ctx, p4RtC, "10.10.10.1", "00:00:00:aa:aa:aa", 1, true)
				Expect(ret).Should(BeNil())
			})

			It("returns err if insert to table fails", func() {
				p4.Errorcase = true
				err := p4.Ipv4ToPortTable(ctx, p4RtC, "10.10.10.1", "00:00:00:aa:aa:aa", 1, true)
				Expect(err).To(HaveOccurred())
			})

			It("returns nil if delete from table is success", func() {
				ret := p4.Ipv4ToPortTable(ctx, p4RtC, "10.10.10.1", "00:00:00:aa:aa:aa", 1, false)
				Expect(ret).Should(BeNil())
			})

			It("returns err if delete from table fails", func() {
				p4.Errorcase = true
				err := p4.Ipv4ToPortTable(ctx, p4RtC, "10.10.10.1", "00:00:00:aa:aa:aa", 1, false)
				Expect(err).To(HaveOccurred())
			})

		})

	})

	Describe("InsertCniRules", func() {

		Context("Programs cni rules", func() {

			It("returns error if IP is invalid", func() {
				ep := store.EndPoint{
					PodIpAddress:  "a.b.c.d",
					InterfaceID:   1,
					PodMacAddress: "00:00:00:aa:aa:aa",
				}
				ep, err := p4.InsertCniRules(ctx, p4RtC, ep, 1)
				Expect(err).To(HaveOccurred())
			})

			It("returns error if MAC is invalid", func() {
				ep := store.EndPoint{
					PodIpAddress:  "10.10.10.1",
					InterfaceID:   1,
					PodMacAddress: "z.z.z.z",
				}
				ep, err := p4.InsertCniRules(ctx, p4RtC, ep, 1)
				Expect(err).To(HaveOccurred())
			})

		})

	})

})

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
	var modBlobPtrDnat = []uint32{1, 2}
	var memberID = []uint32{1, 2}
	var action p4.InterfaceType

	Describe("WriteDestIpTable", func() {

		Context("Programs WriteDestIpTable", func() {

			BeforeEach(func() {
				p4.Env = "test"
				p4.Errorcase = false
			})

			It("returns nil if insert to table is success", func() {
				action = p4.Insert
				ret := p4.WriteDestIpTable(ctx, p4RtC, podIpAddr, portID, modBlobPtrDnat, action)
				Expect(ret).Should(BeNil())
			})

			It("returns err if insert to table fails", func() {
				action = p4.Insert
				p4.Errorcase = true
				err := p4.WriteDestIpTable(ctx, p4RtC, podIpAddr, portID, modBlobPtrDnat, action)
				Expect(err).To(HaveOccurred())
			})

			It("returns nil if delete from table is success", func() {
				action = p4.Delete
				ret := p4.WriteDestIpTable(ctx, p4RtC, podIpAddr, portID, modBlobPtrDnat, action)
				Expect(ret).Should(BeNil())
			})

			It("returns err if delete from table fails", func() {
				action = p4.Delete
				p4.Errorcase = true
				err := p4.WriteDestIpTable(ctx, p4RtC, podIpAddr, portID, modBlobPtrDnat, action)
				Expect(err).To(HaveOccurred())
			})

			It("returns err if action is invalid", func() {
				action = 10
				err := p4.WriteDestIpTable(ctx, p4RtC, podIpAddr, portID, modBlobPtrDnat, action)
				Expect(err).To(HaveOccurred())
			})

		})

	})

	Describe("WriteSourceIpTable", func() {

		Context("Programs WriteSourceIpTable", func() {

			BeforeEach(func() {
				p4.Env = "test"
				p4.Errorcase = false
			})

			It("returns nil if insert to table is success", func() {
				action = p4.Insert
				ret := p4.WriteSourceIpTable(ctx, p4RtC, 1, "10.10.100.1", 20000, action)
				Expect(ret).Should(BeNil())
			})

			It("returns err if insert to table fails", func() {
				action = p4.Insert
				p4.Errorcase = true
				err := p4.WriteSourceIpTable(ctx, p4RtC, 1, "10.10.100.1", 20000, action)
				Expect(err).To(HaveOccurred())
			})

			It("returns nil if delete from table is success", func() {
				action = p4.Delete
				ret := p4.WriteSourceIpTable(ctx, p4RtC, 1, "10.10.100.1", 20000, action)
				Expect(ret).Should(BeNil())
			})

			It("returns err if delete from table fails", func() {
				action = p4.Delete
				p4.Errorcase = true
				err := p4.WriteSourceIpTable(ctx, p4RtC, 1, "10.10.100.1", 20000, action)
				Expect(err).To(HaveOccurred())
			})

			It("returns nil if action is update", func() {
				action = p4.Update
				ret := p4.WriteSourceIpTable(ctx, p4RtC, 1, "10.10.100.1", 20000, action)
				Expect(ret).Should(BeNil())
			})

			It("returns err if action is invalid", func() {
				action = 10
				err := p4.WriteSourceIpTable(ctx, p4RtC, 1, "10.10.100.1", 20000, action)
				Expect(err).To(HaveOccurred())
			})

		})

	})

	Describe("SetMetaTcpTable", func() {

		Context("Programs SetMetaTcpTable", func() {

			BeforeEach(func() {
				p4.Env = "test"
				p4.Errorcase = false
			})

			It("returns nil if insert to table is success", func() {
				action = p4.Insert
				ret := p4.SetMetaTcpTable(ctx, p4RtC, podIpAddr, portID, 1, action)
				Expect(ret).Should(BeNil())
			})

			It("returns err if insert to table fails", func() {
				action = p4.Insert
				p4.Errorcase = true
				err := p4.SetMetaTcpTable(ctx, p4RtC, podIpAddr, portID, 1, action)
				Expect(err).To(HaveOccurred())
			})

			It("returns nil if delete from table is success", func() {
				action = p4.Delete
				ret := p4.SetMetaTcpTable(ctx, p4RtC, podIpAddr, portID, 1, action)
				Expect(ret).Should(BeNil())
			})

			It("returns err if delete from table fails", func() {
				action = p4.Delete
				p4.Errorcase = true
				err := p4.SetMetaTcpTable(ctx, p4RtC, podIpAddr, portID, 1, action)
				Expect(err).To(HaveOccurred())
			})

			It("returns err if action is invalid", func() {
				action = 100
				err := p4.SetMetaTcpTable(ctx, p4RtC, podIpAddr, portID, 1, action)
				Expect(err).To(HaveOccurred())
			})

		})

	})

	Describe("SetMetaUdpTable", func() {

		Context("Programs SetMetaUdpTable", func() {

			BeforeEach(func() {
				p4.Env = "test"
				p4.Errorcase = false
			})

			It("returns nil if insert to table is success", func() {
				action = p4.Insert
				ret := p4.SetMetaUdpTable(ctx, p4RtC, podIpAddr, portID, 1, action)
				Expect(ret).Should(BeNil())
			})

			It("returns err if insert to table fails", func() {
				action = p4.Insert
				p4.Errorcase = true
				err := p4.SetMetaUdpTable(ctx, p4RtC, podIpAddr, portID, 1, action)
				Expect(err).To(HaveOccurred())
			})

			It("returns nil if delete from table is success", func() {
				action = p4.Delete
				ret := p4.SetMetaUdpTable(ctx, p4RtC, podIpAddr, portID, 1, action)
				Expect(ret).Should(BeNil())
			})

			It("returns err if delete from table fails", func() {
				action = p4.Delete
				p4.Errorcase = true
				err := p4.SetMetaUdpTable(ctx, p4RtC, podIpAddr, portID, 1, action)
				Expect(err).To(HaveOccurred())
			})

			It("returns err if action is invalid", func() {
				action = 50
				err := p4.SetMetaUdpTable(ctx, p4RtC, podIpAddr, portID, 1, action)
				Expect(err).To(HaveOccurred())
			})

		})

	})

	Describe("action selector tcp", func() {

		Context("Programs AsSl3TcpTable", func() {

			BeforeEach(func() {
				p4.Env = "test"
				p4.Errorcase = false
				p4.ASelMemError = false
				p4.ASelGrpError = false
			})

			It("returns nil if action profile member and group insert is success", func() {
				action = p4.Insert
				ret := p4.AsSl3TcpTable(ctx, p4RtC, memberID, modBlobPtrDnat, 1, action)
				Expect(ret).Should(BeNil())
			})

			It("returns err if action profile member insert fails", func() {
				action = p4.Insert
				p4.ASelMemError = true
				err := p4.AsSl3TcpTable(ctx, p4RtC, memberID, modBlobPtrDnat, 1, action)
				Expect(err).To(HaveOccurred())
			})

			It("returns nil if action profile member and group delete is success", func() {
				action = p4.Delete
				ret := p4.AsSl3TcpTable(ctx, p4RtC, memberID, modBlobPtrDnat, 1, action)
				Expect(ret).Should(BeNil())
			})

			It("returns err if action profile member delete fails", func() {
				action = p4.Delete
				p4.ASelMemError = true
				err := p4.AsSl3TcpTable(ctx, p4RtC, memberID, modBlobPtrDnat, 1, action)
				Expect(err).To(HaveOccurred())
			})

			It("returns err if action profile group insert fails", func() {
				action = p4.Insert
				p4.ASelGrpError = true
				err := p4.AsSl3TcpTable(ctx, p4RtC, memberID, modBlobPtrDnat, 1, action)
				Expect(err).To(HaveOccurred())
			})

			It("returns err if action profile group delete fails", func() {
				action = p4.Delete
				p4.ASelGrpError = true
				err := p4.AsSl3TcpTable(ctx, p4RtC, memberID, modBlobPtrDnat, 1, action)
				Expect(err).To(HaveOccurred())
			})

			It("returns err if action is invalid", func() {
				action = 50
				err := p4.AsSl3TcpTable(ctx, p4RtC, memberID, modBlobPtrDnat, 1, action)
				Expect(err).To(HaveOccurred())
			})

		})

	})

	Describe("action selector udp", func() {

		Context("Programs AsSl3UdpTable", func() {

			BeforeEach(func() {
				p4.Env = "test"
				p4.Errorcase = false
				p4.ASelMemError = false
				p4.ASelGrpError = false
			})

			It("returns nil if action profile member and group insert is success", func() {
				action = p4.Insert
				ret := p4.AsSl3UdpTable(ctx, p4RtC, memberID, modBlobPtrDnat, 1, action)
				Expect(ret).Should(BeNil())
			})

			It("returns err if action profile member insert fails", func() {
				action = p4.Insert
				p4.ASelMemError = true
				err := p4.AsSl3UdpTable(ctx, p4RtC, memberID, modBlobPtrDnat, 1, action)
				Expect(err).To(HaveOccurred())
			})

			It("returns nil if action profile member and group delete is success", func() {
				action = p4.Delete
				ret := p4.AsSl3UdpTable(ctx, p4RtC, memberID, modBlobPtrDnat, 1, action)
				Expect(ret).Should(BeNil())
			})

			It("returns err if action profile member delete fails", func() {
				action = p4.Delete
				p4.ASelMemError = true
				err := p4.AsSl3UdpTable(ctx, p4RtC, memberID, modBlobPtrDnat, 1, action)
				Expect(err).To(HaveOccurred())
			})

			It("returns err if action profile group insert fails", func() {
				action = p4.Insert
				p4.ASelGrpError = true
				err := p4.AsSl3UdpTable(ctx, p4RtC, memberID, modBlobPtrDnat, 1, action)
				Expect(err).To(HaveOccurred())
			})

			It("returns err if action profile group delete fails", func() {
				action = p4.Delete
				p4.ASelGrpError = true
				err := p4.AsSl3UdpTable(ctx, p4RtC, memberID, modBlobPtrDnat, 1, action)
				Expect(err).To(HaveOccurred())
			})

			It("returns err if action is invalid", func() {
				action = 25
				err := p4.AsSl3UdpTable(ctx, p4RtC, memberID, modBlobPtrDnat, 1, action)
				Expect(err).To(HaveOccurred())
			})

		})

	})

	Describe("TxBalanceTcpTable", func() {

		Context("Programs TxBalanceTcpTable", func() {

			BeforeEach(func() {
				p4.Env = "test"
				p4.Errorcase = false
			})

			It("returns nil if insert to table is success", func() {
				action = p4.Insert
				ret := p4.TxBalanceTcpTable(ctx, p4RtC, "10.10.100.1", 20000, 1, action)
				Expect(ret).Should(BeNil())
			})

			It("returns err if insert to table fails", func() {
				action = p4.Insert
				p4.Errorcase = true
				err := p4.TxBalanceTcpTable(ctx, p4RtC, "10.10.100.1", 20000, 1, action)
				Expect(err).To(HaveOccurred())
			})

			It("returns nil if delete from table is success", func() {
				action = p4.Delete
				ret := p4.TxBalanceTcpTable(ctx, p4RtC, "10.10.100.1", 20000, 1, action)
				Expect(ret).Should(BeNil())
			})

			It("returns err if delete from table fails", func() {
				action = p4.Delete
				p4.Errorcase = true
				err := p4.TxBalanceTcpTable(ctx, p4RtC, "10.10.100.1", 20000, 1, action)
				Expect(err).To(HaveOccurred())
			})

			It("returns nil if action is update", func() {
				action = p4.Update
				ret := p4.TxBalanceTcpTable(ctx, p4RtC, "10.10.100.1", 20000, 1, action)
				Expect(ret).Should(BeNil())
			})

			It("returns err if action is invalid", func() {
				action = 80
				err := p4.TxBalanceTcpTable(ctx, p4RtC, "10.10.100.1", 20000, 1, action)
				Expect(err).To(HaveOccurred())
			})

		})

	})

	Describe("TxBalanceUdpTable", func() {

		Context("Programs TxBalanceUdpTable", func() {

			BeforeEach(func() {
				p4.Env = "test"
				p4.Errorcase = false
			})

			It("returns nil if insert to table is success", func() {
				action = p4.Insert
				ret := p4.TxBalanceUdpTable(ctx, p4RtC, "10.10.100.1", 20000, 1, action)
				Expect(ret).Should(BeNil())
			})

			It("returns err if insert to table fails", func() {
				action = p4.Insert
				p4.Errorcase = true
				err := p4.TxBalanceUdpTable(ctx, p4RtC, "10.10.100.1", 20000, 1, action)
				Expect(err).To(HaveOccurred())
			})

			It("returns nil if delete from table is success", func() {
				action = p4.Delete
				ret := p4.TxBalanceUdpTable(ctx, p4RtC, "10.10.100.1", 20000, 1, action)
				Expect(ret).Should(BeNil())
			})

			It("returns err if delete from table fails", func() {
				action = p4.Delete
				p4.Errorcase = true
				err := p4.TxBalanceUdpTable(ctx, p4RtC, "10.10.100.1", 20000, 1, action)
				Expect(err).To(HaveOccurred())
			})

			It("returns nil if action is Update", func() {
				action = p4.Update
				ret := p4.TxBalanceUdpTable(ctx, p4RtC, "10.10.100.1", 20000, 1, action)
				Expect(ret).Should(BeNil())
			})

			It("returns err if action is invalid", func() {
				action = 90
				err := p4.TxBalanceUdpTable(ctx, p4RtC, "10.10.100.1", 20000, 1, action)
				Expect(err).To(HaveOccurred())
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
				err, _ := p4.InsertServiceRules(ctx, p4RtC, podIpAddr, portID, service, false, false)
				Expect(err).To(HaveOccurred())
			})

		})

	})

	Describe("DeleteServiceRules", func() {

		Context("deletes service rules", func() {

			It("returns error if entry is not found", func() {
				store.NewService()
				service := store.Service{
					ClusterIp: "10.100.1.1",
					Port:      10000,
					Proto:     "TCP",
				}
				err := p4.DeleteServiceRules(ctx, p4RtC, service)
				Expect(err).To(HaveOccurred())
			})

		})

	})

})
