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

package p4

import (
	"context"
	"fmt"
	"github.com/antoninbas/p4runtime-go-client/pkg/client"
	"github.com/ipdk-io/k8s-infra-offload/pkg/inframanager/store"
	log "github.com/sirupsen/logrus"
	"net"
)

var Env string
var P4w P4RtCWrapper

func ArptToPortTable(ctx context.Context, p4RtC *client.Client, arpTpa string, port uint32, flag bool) error {
	var err error
	P4w = GetP4Wrapper(Env)

	if flag == true {
		entryAdd := P4w.NewTableEntry(
			p4RtC,
			"main.k8s_dp_control.arp_to_port_table",
			map[string]client.MatchInterface{
				"hdrs.arp.tpa": &client.ExactMatch{
					Value: Pack32BinaryIP4(arpTpa),
				},
			},
			P4w.NewTableActionDirect(p4RtC, "k8s_dp_control.set_dest_vport",
				[][]byte{ValueToBytes16(uint16(port))}),
			nil,
		)
		if err = P4w.InsertTableEntry(ctx, p4RtC, entryAdd); err != nil {
			log.Errorf("Cannot insert entry into arp_to_port_table table, ip: %s, port: %d, err: %v",
				arpTpa, port, err)
			return err
		}
		log.Infof("Inserted entry in 'ArptToPortTable', ip: %s, port: %d", arpTpa, port)
	} else {
		entryDelete := P4w.NewTableEntry(
			p4RtC,
			"main.k8s_dp_control.arp_to_port_table",
			map[string]client.MatchInterface{
				"hdrs.arp.tpa": &client.ExactMatch{
					Value: Pack32BinaryIP4(arpTpa),
				},
			},
			nil,
			nil,
		)
		if err = P4w.DeleteTableEntry(ctx, p4RtC, entryDelete); err != nil {
			log.Errorf("Cannot delete entry from arp_to_port_table table, ip: %s, err: %v",
				arpTpa, err)
			return err
		}
	}

	return nil
}

func GWMacModTable(ctx context.Context, p4RtC *client.Client, ipAddr string,
	port uint16, macAddr string, modPtr uint32, flag bool) error {

	var err error
	P4w = GetP4Wrapper(Env)

	mac, err := net.ParseMAC(macAddr)
	if err != nil {
		log.Errorf("Invalid format, failed to parse mac: %v", err)
		return err
	}

	if flag == true {

		entry := P4w.NewTableEntry(
			p4RtC,
			"main.k8s_dp_control.pod_gateway_mac_mod_table",
			map[string]client.MatchInterface{
				"meta.common.mod_blob_ptr": &client.ExactMatch{
					Value: ValueToBytes(modPtr),
				},
			},
			P4w.NewTableActionDirect(p4RtC, "k8s_dp_control.update_src_dst_mac", [][]byte{mac}),
			nil,
		)
		if err = P4w.InsertTableEntry(ctx, p4RtC, entry); err != nil {
			log.Errorf("Failed to add entry in pod_gateway_mac_mod table: mod ptr: %d, mac: %s, err: %v", modPtr, mac, err)
			return err
		}

	} else {

		entry := P4w.NewTableEntry(
			p4RtC,
			"main.k8s_dp_control.pod_gateway_mac_mod_table",
			map[string]client.MatchInterface{
				"meta.common.mod_blob_ptr": &client.ExactMatch{
					Value: ValueToBytes(modPtr),
				},
			},
			nil,
			nil,
		)
		if err = P4w.DeleteTableEntry(ctx, p4RtC, entry); err != nil {
			log.Errorf("Failed to delete entry from pod_gateway_mac_mod table for mod ptr: %d, err: %v",
				modPtr, err)
			return err
		}
	}

	return nil
}

func Ipv4ToPortTable(ctx context.Context, p4RtC *client.Client,
	ipAddr string, port uint32, modPtr uint32, flag bool) error {
	var err error
	P4w = GetP4Wrapper(Env)

	if flag == true {

		entryAdd := P4w.NewTableEntry(
			p4RtC,
			"main.k8s_dp_control.ipv4_to_port_table_tx",
			map[string]client.MatchInterface{
				"hdrs.ipv4[meta.common.depth].dst_ip": &client.ExactMatch{
					Value: Pack32BinaryIP4(ipAddr),
				},
			},
			P4w.NewTableActionDirect(
				p4RtC,
				"k8s_dp_control.set_dest_mac_vport",
				[][]byte{ValueToBytes16(uint16(port)), ValueToBytes(modPtr)}),
			nil,
		)
		if err = P4w.InsertTableEntry(ctx, p4RtC, entryAdd); err != nil {
			log.Errorf("Failed to add entry in ipv4_to_port tx table, ip addr: %s, modptr: %d, err: %v", ipAddr, modPtr, err)
			return err
		}

		entry2 := P4w.NewTableEntry(
			p4RtC,
			"main.k8s_dp_control.ipv4_to_port_table_rx",
			map[string]client.MatchInterface{
				"hdrs.ipv4[meta.common.depth].dst_ip": &client.ExactMatch{
					Value: Pack32BinaryIP4(ipAddr),
				},
			},
			P4w.NewTableActionDirect(
				p4RtC,
				"k8s_dp_control.set_dest_vport",
				[][]byte{ValueToBytes16(uint16(port))}),
			nil,
		)
		if err := P4w.InsertTableEntry(ctx, p4RtC, entry2); err != nil {
			log.Errorf("Failed to add entry in ipv4_to_port rx table, ip addr: %s, port: %d, err: %v", ipAddr, port, err)
			return err
		}
	} else {

		entry := P4w.NewTableEntry(
			p4RtC,
			"main.k8s_dp_control.ipv4_to_port_table_tx",
			map[string]client.MatchInterface{
				"hdrs.ipv4[meta.common.depth].dst_ip": &client.ExactMatch{
					Value: Pack32BinaryIP4(ipAddr),
				},
			},
			nil,
			nil,
		)
		if err = P4w.DeleteTableEntry(ctx, p4RtC, entry); err != nil {
			log.Errorf("Failed to delete entry %s from ipv4_to_port tx table: %v", ipAddr, err)
			return err
		}

		entry2 := P4w.NewTableEntry(
			p4RtC,
			"main.k8s_dp_control.ipv4_to_port_table_rx",
			map[string]client.MatchInterface{
				"hdrs.ipv4[meta.common.depth].dst_ip": &client.ExactMatch{
					Value: Pack32BinaryIP4(ipAddr),
				},
			},
			nil,
			nil,
		)
		if err = P4w.DeleteTableEntry(ctx, p4RtC, entry2); err != nil {
			log.Errorf("Failed to delete entry %s from ipv4_to_port rx table: %v", ipAddr, err)
			return err
		}
	}

	return nil
}

func InsertCniRules(ctx context.Context, p4RtC *client.Client, ep store.EndPoint,
	ifaceType InterfaceType) (store.EndPoint, error) {

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
		return ep, err
	}

	ep.ModPtr = uuidFactory.getUUID()

	err = Ipv4ToPortTable(ctx, p4RtC, ep.PodIpAddress, ep.InterfaceID,
		ep.ModPtr, true)
	if err != nil {
		return ep, err
	}

	err = GWMacModTable(ctx, p4RtC, ep.PodIpAddress, uint16(ep.InterfaceID),
		ep.PodMacAddress, ep.ModPtr, true)
	if err != nil {
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

	err = Ipv4ToPortTable(ctx, p4RtC, ep.PodIpAddress, 0, 0, false)
	if err != nil {
		return err
	}

	err = GWMacModTable(ctx, p4RtC, ep.PodIpAddress, 0, ep.PodMacAddress,
		ep.ModPtr, false)
	if err != nil {
		return err
	}

	return nil
}
