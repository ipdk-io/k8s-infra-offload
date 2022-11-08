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

package p4

import (
	"context"
	"github.com/antoninbas/p4runtime-go-client/pkg/client"
	p4_v1 "github.com/p4lang/p4runtime/go/p4/v1"
	log "github.com/sirupsen/logrus"
	"net"
)

func WriteDestIpTableEntry(ctx context.Context, p4RtC *client.Client, podIpAddr []string, podMacAddr []string, modBlobPtr []uint32) error {
	var err error
	for i := 0; i < len(modBlobPtr); i++ {
		dstMac, err := net.ParseMAC(podMacAddr[i])
		if err != nil {
			log.Errorf("Failed to parse mac address %s", podMacAddr[i])
			return err
		}

		entry1 := p4RtC.NewTableEntry(
			"k8s_dp_control.write_dest_ip_table",
			map[string]client.MatchInterface{
				"meta.mod_blob_ptr": &client.ExactMatch{
					Value: valueToBytes(modBlobPtr[i]),
				},
			},
			p4RtC.NewTableActionDirect("k8s_dp_control.update_dst_ip_mac", [][]byte{dstMac, net.ParseIP(podIpAddr[i])}),
			nil,
		)
		if err := p4RtC.InsertTableEntry(ctx, entry1); err != nil {
			log.Errorf("Cannot insert entry in 'direction_table table': %v", err)
		}
	}
	return err
}

func AsSl3TableEntry(ctx context.Context, p4RtC *client.Client, memberID []uint32, modBlobPtr []uint32, interfaceID []uint32, groupID uint32) error {
	/*»	var memberList []*p4_v1.ActionProfileGroup_Member = []*p4_v1.ActionProfileGroup_Member{&p4_v1.ActionProfileGroup_Member{
	  »	»	MemberId: uint32(1),
	  »	},
	  »	»	&p4_v1.ActionProfileGroup_Member{
	  »	»	»	MemberId: uint32(2),
	  »	»	}}*/
	var err error
	var memberList []*p4_v1.ActionProfileGroup_Member
	for j := 0; j < len(memberID); j++ {
		member := &p4_v1.ActionProfileGroup_Member{
			MemberId: memberID[j],
		}
		memberList = append(memberList, member)
	}

	for i := 0; i < len(memberID); i++ {
		member := &p4_v1.ActionProfileGroup_Member{
			MemberId: memberID[i],
		}
		memberList = append(memberList, member)

		entry1 := p4RtC.NewActionProfileMember(
			"k8s_dp_control.as_sl3",
			memberID[i],
			"k8s_dp_control.set_default_lb_dest",
			[][]byte{valueToBytes(interfaceID[i]), valueToBytes(modBlobPtr[i])},
		)
		if err := p4RtC.InsertActionProfileMember(ctx, entry1); err != nil {
			log.Errorf("Cannot insert member entry in 'as_sl3 table': %v", err)
		}
	}

	entry2 := p4RtC.NewActionProfileGroup(
		"k8s_dp_control.as_sl3",
		groupID,
		memberList,
		int32(124),
	)
	if err := p4RtC.InsertActionProfileGroup(ctx, entry2); err != nil {
		log.Errorf("Cannot insert group entry in 'as_sl3 table': %v", err)
	}

	return err
}

func TxBalanceIpTableEntry(ctx context.Context, p4RtC *client.Client, serviceIpAddr string, servicePort uint32, groupID uint32) error {
	var err error
	mfs := map[string]client.MatchInterface{
		"hdr.ipv4.dst_addr": &client.ExactMatch{
			Value: net.ParseIP(serviceIpAddr),
		},
		"hdr.tcp.dst_port": &client.ExactMatch{
			Value: valueToBytes(servicePort),
		},
	}
	entry1 := p4RtC.NewTableEntry(
		"k8s_dp_control.tx_balance",
		mfs,
		p4RtC.NewTableActionGroup(groupID),
		nil,
	)
	if err := p4RtC.InsertTableEntry(ctx, entry1); err != nil {
		log.Errorf("Cannot insert entry in 'tx_balance table': %v", err)
	}
	return err
}

func WriteSourceIpTableEntry(ctx context.Context, p4RtC *client.Client, rxModBlobPtr uint32, serviceIpAddr string, serviceMacAddr string) error {
	var err error
	srcMac, err := net.ParseMAC(serviceMacAddr)
	if err != nil {
		log.Errorf("Failed to parse mac address %s", serviceMacAddr)
		return err
	}

	entry1 := p4RtC.NewTableEntry(
		"k8s_dp_control.write_source_ip_table",
		map[string]client.MatchInterface{
			"meta.mod_blob_ptr": &client.ExactMatch{
				Value: valueToBytes(rxModBlobPtr),
			},
		},
		p4RtC.NewTableActionDirect("k8s_dp_control.update_src_ip_mac", [][]byte{srcMac, net.ParseIP(serviceIpAddr)}),
		nil,
	)
	if err := p4RtC.InsertTableEntry(ctx, entry1); err != nil {
		log.Errorf("Cannot insert entry in 'write_source_ip_table table': %v", err)
	}
	return err
}

func RxSrcIpTableEntry(ctx context.Context, p4RtC *client.Client, podIpAddr []string, rxModBlobPtr uint32) error {
	var err error
	for i := 0; i < len(podIpAddr); i++ {
		entry1 := p4RtC.NewTableEntry(
			"k8s_dp_control.rx_src_ip",
			map[string]client.MatchInterface{
				"hdr.ipv4.src_addr": &client.ExactMatch{
					Value: net.ParseIP(podIpAddr[i]),
				},
			},
			p4RtC.NewTableActionDirect("k8s_dp_control.set_source_ip", [][]byte{valueToBytes(rxModBlobPtr)}),
			nil,
		)
		if err := p4RtC.InsertTableEntry(ctx, entry1); err != nil {
			log.Errorf("Cannot insert entry in 'rx_src_ip table': %v", err)
		}
	}
	return err
}

func insertServiceRules(ctx context.Context, p4RtC *client.Client, podIpAddr []string, podMacAddr []string, serviceIpAddr string, serviceMacAddr string, servicePort uint32) error {
	var err error
	memberID := make([]uint32, len(podIpAddr))
	interfaceID := make([]uint32, len(podIpAddr))

	groupID := uuidFactory.getUUID()

	for i := 0; i < len(podIpAddr); i++ {
		memberID = append(memberID, uint32(i+1))
		interfaceID = append(interfaceID, 0)
	}

	err = WriteDestIpTableEntry(ctx, p4RtC, podIpAddr, podMacAddr, memberID)
	err = AsSl3TableEntry(ctx, p4RtC, memberID, memberID, interfaceID, groupID)
	err = TxBalanceIpTableEntry(ctx, p4RtC, serviceIpAddr, servicePort, groupID)
	err = WriteSourceIpTableEntry(ctx, p4RtC, groupID, serviceIpAddr, serviceMacAddr)
	err = RxSrcIpTableEntry(ctx, p4RtC, podIpAddr, groupID)

	return err
}
