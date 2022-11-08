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
	log "github.com/sirupsen/logrus"
	"net"
)

func insertMacToPortTableEntry(ctx context.Context, p4RtC *client.Client, macAddr string, port uint32) error {
	var err error
	mac, err := net.ParseMAC(macAddr)
	if err != nil {
		log.Errorf("Failed to parse mac address %s", macAddr)
		return err
	}

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
	mac, err := net.ParseMAC(macAddr)
	if err != nil {
		log.Errorf("Failed to parse mac address %s", macAddr)
		return err
	}

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

func InsertCniRules(ctx context.Context, p4RtC *client.Client, macAddr string, ipAddr string, portId int, ifaceType InterfaceType) error {
	/*
		TODO. Distinguish for interface type
		and program the rules accordingly.
	*/

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
