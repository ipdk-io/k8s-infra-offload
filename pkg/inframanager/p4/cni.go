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
	"github.com/ipdk-io/k8s-infra-offload/pkg/inframanager/store"
	log "github.com/sirupsen/logrus"
	"net"
)

func ArptToPortTable(ctx context.Context, p4RtC *client.Client, arpTpa string, port uint32, flag bool) error {
	var err error
	P4w = GetP4Wrapper(Env)

	if flag == true {
		entryAdd := P4w.NewTableEntry(
			p4RtC,
			"k8s_dp_control.arpt_to_port_table",
			map[string]client.MatchInterface{
				"hdr.arp.tpa": &client.ExactMatch{
					Value: Pack32BinaryIP4(arpTpa),
				},
			},
			P4w.NewTableActionDirect(p4RtC, "k8s_dp_control.set_dest_vport", [][]byte{ValueToBytes(port)}),
			nil,
		)
		if err = P4w.InsertTableEntry(ctx, p4RtC, entryAdd); err != nil {
			log.Errorf("Cannot insert entry into arpt_to_port_table table, ip: %s, port: %d, err: %v",
				arpTpa, port, err)
			return err
		}
	} else {
		entryDelete := P4w.NewTableEntry(
			p4RtC,
			"k8s_dp_control.arpt_to_port_table",
			map[string]client.MatchInterface{
				"hdr.arp.tpa": &client.ExactMatch{
					Value: Pack32BinaryIP4(arpTpa),
				},
			},
			nil,
			nil,
		)
		if err = P4w.DeleteTableEntry(ctx, p4RtC, entryDelete); err != nil {
			log.Errorf("Cannot delete entry from arpt_to_port_table table, ip: %s, port: %d, err: %v",
				arpTpa, port, err)
			return err
		}
	}

	return nil
}

func Ipv4ToPortTable(ctx context.Context, p4RtC *client.Client, ipAddr string, macAddr string, port uint32, flag bool) error {
	var err error
	P4w = GetP4Wrapper(Env)

	if flag == true {
		dmac, err := net.ParseMAC(macAddr)
		if err != nil {
			log.Errorf("Invalid mac address %s", macAddr)
			return err
		}

		entryAdd := P4w.NewTableEntry(
			p4RtC,
			"k8s_dp_control.ipv4_to_port_table",
			map[string]client.MatchInterface{
				"hdr.ipv4.dst_addr": &client.ExactMatch{
					Value: Pack32BinaryIP4(ipAddr),
				},
			},
			//TODO: properly handle k8s_dp_control.send
			P4w.NewTableActionDirect(p4RtC, "k8s_dp_control.set_dest_mac_vport", [][]byte{ValueToBytes(port), dmac}),
			nil,
		)
		if err = P4w.InsertTableEntry(ctx, p4RtC, entryAdd); err != nil {
			log.Errorf("Cannot insert entry into ipv4_to_port_table table: %v", err)
			return err
		}
	} else {
		entry := P4w.NewTableEntry(
			p4RtC,
			"k8s_dp_control.ipv4_to_port_table",
			map[string]client.MatchInterface{
				"hdr.ipv4.dst_addr": &client.ExactMatch{
					Value: Pack32BinaryIP4(ipAddr),
				},
			},
			nil,
			nil,
		)
		if err = P4w.DeleteTableEntry(ctx, p4RtC, entry); err != nil {
			log.Errorf("Cannot delete entry from ipv4_to_port_table table: %v", err)
			return err
		}
	}

	return nil
}

func InsertCniRules(ctx context.Context, p4RtC *client.Client, ep store.EndPoint,
	ifaceType InterfaceType) (store.EndPoint, error) {
	/*
		TODO. Distinguish for interface type
		and program the rules accordingly.
	*/
	if net.ParseIP(ep.PodIpAddress) == nil {
		err := fmt.Errorf("Invalid IP Address")
		return ep, err
	}

	_, err := net.ParseMAC(ep.PodMacAddress)
	if err != nil {
		err = fmt.Errorf("Invalid MAC Address")
		return ep, err
	}

	err = ArptToPortTable(ctx, p4RtC, ep.PodIpAddress, ep.InterfaceID, true)
	if err != nil {
		log.Infof("Failed to insert into ArptToPortTable, err: %s", err)
		return ep, err
	}

	err = Ipv4ToPortTable(ctx, p4RtC, ep.PodIpAddress, ep.PodMacAddress, ep.InterfaceID, true)
	if err != nil {
		log.Infof("Failed to insert into Ipv4ToPortTable, err: %s", err)
		return ep, err
	}

	return ep, nil
}

func DeleteCniRules(ctx context.Context, p4RtC *client.Client, ep store.EndPoint) error {
	if net.ParseIP(ep.PodIpAddress) == nil {
		err := fmt.Errorf("Invalid IP Address")
		return err
	}

	err := ArptToPortTable(ctx, p4RtC, ep.PodIpAddress, 0, false)
	if err != nil {
		return err
	}

	err = Ipv4ToPortTable(ctx, p4RtC, ep.PodIpAddress, "", 0, false)
	if err != nil {
		return err
	}

	return nil
}
