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
	"fmt"
	"github.com/antoninbas/p4runtime-go-client/pkg/client"
	log "github.com/sirupsen/logrus"
	"net"
)

func ArptToPortTable(ctx context.Context, p4RtC *client.Client, arpTpa string, port uint32, flag bool) error {
	var err error

	if net.ParseIP(arpTpa) == nil {
		err = fmt.Errorf("Invalid IP Address")
		return err
	}

	if flag == true {
		entryAdd := p4RtC.NewTableEntry(
			"k8s_dp_control.arpt_to_port_table",
			map[string]client.MatchInterface{
				"hdr.arp.tpa": &client.ExactMatch{
					Value: Pack32BinaryIP4(arpTpa),
				},
			},
			p4RtC.NewTableActionDirect("k8s_dp_control.set_dest_vport", [][]byte{valueToBytes(port)}),
			nil,
		)
		if err = p4RtC.InsertTableEntry(ctx, entryAdd); err != nil {
			log.Errorf("Cannot insert entry into arpt_to_port_table table: %v", err)
			return err
		}
	} else {
		entryDelete := p4RtC.NewTableEntry(
			"k8s_dp_control.arpt_to_port_table",
			map[string]client.MatchInterface{
				"hdr.arp.tpa": &client.ExactMatch{
					Value: Pack32BinaryIP4(arpTpa),
				},
			},
			nil,
			nil,
		)
		if err = p4RtC.DeleteTableEntry(ctx, entryDelete); err != nil {
			log.Errorf("Cannot delete entry from arpt_to_port_table table: %v", err)
			return err
		}
	}

	return nil
}

func Ipv4ToPortTable(ctx context.Context, p4RtC *client.Client, ipAddr string, macAddr string, port uint32, flag bool) error {
	var err error

	if net.ParseIP(ipAddr) == nil {
		err = fmt.Errorf("Invalid IP Address")
		return err
	}

	if flag == true {
		dmac, err := net.ParseMAC(macAddr)
		if err != nil {
			log.Errorf("Invalid mac address %s", macAddr)
			return err
		}

		entryAdd := p4RtC.NewTableEntry(
			"k8s_dp_control.ipv4_to_port_table",
			map[string]client.MatchInterface{
				"hdr.ipv4.dst_addr": &client.ExactMatch{
					Value: Pack32BinaryIP4(ipAddr),
				},
			},
			//TODO: properly handle k8s_dp_control.send
			p4RtC.NewTableActionDirect("k8s_dp_control.set_dest_mac_vport", [][]byte{valueToBytes(port), dmac}),
			nil,
		)
		if err = p4RtC.InsertTableEntry(ctx, entryAdd); err != nil {
			log.Errorf("Cannot insert entry into ipv4_to_port_table table: %v", err)
			return err
		}
	} else {
		entry := p4RtC.NewTableEntry(
			"k8s_dp_control.ipv4_to_port_table",
			map[string]client.MatchInterface{
				"hdr.ipv4.dst_addr": &client.ExactMatch{
					Value: Pack32BinaryIP4(ipAddr),
				},
			},
			nil,
			nil,
		)
		if err = p4RtC.DeleteTableEntry(ctx, entry); err != nil {
			log.Errorf("Cannot delete entry from ipv4_to_port_table table: %v", err)
			return err
		}
	}

	return nil
}

func InsertCniRules(ctx context.Context, p4RtC *client.Client, macAddr string, ipAddr string, portId int, ifaceType InterfaceType) error {
	/*
		TODO. Distinguish for interface type
		and program the rules accordingly.
	*/
	err := ArptToPortTable(ctx, p4RtC, ipAddr, uint32(portId), true)
	if err != nil {
		return err
	}

	err = Ipv4ToPortTable(ctx, p4RtC, ipAddr, macAddr, uint32(portId), true)
	if err != nil {
		return err
	}

	return nil
}

func DeleteCniRules(ctx context.Context, p4RtC *client.Client, macAddr string, ipAddr string) error {
	err := ArptToPortTable(ctx, p4RtC, ipAddr, 0, false)
	if err != nil {
		return err
	}

	err = Ipv4ToPortTable(ctx, p4RtC, ipAddr, "", 0, false)
	if err != nil {
		return err
	}

	return nil
}
