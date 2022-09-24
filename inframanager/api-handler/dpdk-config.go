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

package api_handler

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"github.com/antoninbas/p4runtime-go-client/pkg/client"
	p4_v1 "github.com/p4lang/p4runtime/go/p4/v1"
	log "github.com/sirupsen/logrus"
	"math/big"
	"net"
)

const (
	MAXUINT32              = 4294967295
	DEFAULT_UUID_CNT_CACHE = 512
)

type UUIDGenerator struct {
	idGen        uint32
	internalChan chan uint32
}

func newUUIDGenerator() *UUIDGenerator {
	gen := &UUIDGenerator{
		idGen:        0,
		internalChan: make(chan uint32, DEFAULT_UUID_CNT_CACHE),
	}
	gen.startGen()
	return gen
}

// Open goroutine and put the generated UUID in digital form into the buffer pipe
func (this *UUIDGenerator) startGen() {
	go func() {
		for {
			if this.idGen == MAXUINT32 {
				this.idGen = 1
			} else {
				this.idGen += 1
			}
			this.internalChan <- this.idGen
		}
	}()
}

// Get UUID in uint32 form
func (this *UUIDGenerator) getUUID() uint32 {
	return <-this.internalChan
}

var uuidFactory = newUUIDGenerator()

func valueToBytes(value uint32) []byte {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, value)
	if err != nil {
		fmt.Println("binary.Write failed:", err)
	}
	fmt.Printf("% x", buf.Bytes())
	return buf.Bytes()
}

func IP4toInt(IPv4Address net.IP) int64 {
	IPv4Int := big.NewInt(0)
	IPv4Int.SetBytes(IPv4Address.To4())
	return IPv4Int.Int64()
}

func Pack32BinaryIP4(ip4Address string) []byte {
	ipv4Decimal := IP4toInt(net.ParseIP(ip4Address))

	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, uint32(ipv4Decimal))

	if err != nil {
		fmt.Println("Unable to write to buffer:", err)
	}

	// present in hexadecimal format
	//fmt.Sprintf("%x", buf.Bytes())
	return buf.Bytes()
}

func insertMacToPortTableEntry(ctx context.Context, p4RtC *client.Client, macAddr string, port uint32) error {
	var err error
	mac, _ := net.ParseMAC(macAddr)
	entry := p4RtC.NewTableEntry(
		"k8s_dp_control.mac_to_port_table",
		map[string]client.MatchInterface{
			"hdr.ethernet.dst_mac": &client.ExactMatch{
				Value: mac,
			},
		},
		p4RtC.NewTableActionDirect("k8s_dp_control.set_dest_vport", [][]byte{valueToBytes(port)}),
		nil,
	)
	if err = p4RtC.InsertTableEntry(ctx, entry); err != nil {
		log.Errorf("Cannot insert entry in 'mac_to_port_table': %v", err)
	}

	return err
}

func deleteMacToPortTableEntry(ctx context.Context, p4RtC *client.Client, macAddr string) error {
	var err error
	mac, _ := net.ParseMAC(macAddr)
	entry := p4RtC.NewTableEntry(
		"k8s_dp_control.mac_to_port_table",
		map[string]client.MatchInterface{
			"hdr.ethernet.dst_mac": &client.ExactMatch{
				Value: mac,
			},
		},
		nil,
		nil,
	)
	if err = p4RtC.DeleteTableEntry(ctx, entry); err != nil {
		log.Errorf("Cannot delete entry from 'mac_to_port_table': %v", err)
	}

	return err
}

func insertIpv4ToPortTableEntry(ctx context.Context, p4RtC *client.Client, arpTpa string, port uint32) error {
	var err error
	entry := p4RtC.NewTableEntry(
		"k8s_dp_control.ipv4_to_port_table",
		map[string]client.MatchInterface{
			"hdr.arp.tpa": &client.LpmMatch{
				Value: Pack32BinaryIP4(arpTpa),
				PLen:  int32(32),
			},
		},
		//TODO: properly handle k8s_dp_control.send
		p4RtC.NewTableActionDirect("k8s_dp_control.set_dest_vport", [][]byte{valueToBytes(port)}),
		nil,
	)
	if err = p4RtC.InsertTableEntry(ctx, entry); err != nil {
		log.Errorf("Cannot insert entry in ipv4_to_port_table table: %v", err)
	}

	return err
}

func deleteIpv4ToPortTableEntry(ctx context.Context, p4RtC *client.Client, arpTpa string) error {
	var err error
	entry := p4RtC.NewTableEntry(
		"k8s_dp_control.ipv4_to_port_table",
		map[string]client.MatchInterface{
			"hdr.arp.tpa": &client.LpmMatch{
				Value: Pack32BinaryIP4(arpTpa),
				PLen:  int32(32),
			},
		},
		nil,
		nil,
	)
	if err = p4RtC.DeleteTableEntry(ctx, entry); err != nil {
		log.Errorf("Cannot delete entry from ipv4_to_port_table table: %v", err)
	}

	return err
}

func InsertCniRules(ctx context.Context, p4RtC *client.Client, macAddr string, ipAddr string, portId int) error {
	//interfaceID := (uint32)portId
	err := insertIpv4ToPortTableEntry(ctx, p4RtC, ipAddr, uint32(portId))
	if err != nil {
		return err
	}

	err = insertMacToPortTableEntry(ctx, p4RtC, macAddr, uint32(portId))
	if err != nil {
		return err
	}

	return nil
}

func DeleteCniRules(ctx context.Context, p4RtC *client.Client, macAddr string, ipAddr string) error {
	err := deleteIpv4ToPortTableEntry(ctx, p4RtC, ipAddr)
	if err != nil {
		return err
	}

	err = deleteMacToPortTableEntry(ctx, p4RtC, macAddr)
	if err != nil {
		return err
	}

	return nil
}

func WriteDestIpTableEntry(ctx context.Context, p4RtC *client.Client, podIpAddr []string, podMacAddr []string, modBlobPtr []uint32) error {
	var err error
	for i := 0; i < len(modBlobPtr); i++ {
		dstMac, _ := net.ParseMAC(podMacAddr[i])
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
	srcMac, _ := net.ParseMAC(serviceMacAddr)
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
