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
	"net"

	"github.com/antoninbas/p4runtime-go-client/pkg/client"
	"github.com/ipdk-io/k8s-infra-offload/pkg/inframanager/store"
	"github.com/ipdk-io/k8s-infra-offload/pkg/types"
	log "github.com/sirupsen/logrus"
)

func ArpToPortDefault(ctx context.Context, p4RtC *client.Client, arpTpa string, port uint32) error {
	cniarpmap := make(map[string][]UpdateTable)

	P4w = GetP4Wrapper(Env)
	tablenames := []string{"k8s_dp_control.arp_to_port_table"}
	actionnames := []string{"k8s_dp_control.set_dest_vport"}

	arpkeymatchtype := []string{"Exact"}
	arpkeyNames := []string{"hdrs.arp.tpa"}
	arpkeyparams := make([]interface{}, 0)
	arpkeyparams = append(arpkeyparams, Pack32BinaryIP4(arpTpa))
	arpactionparams := make([]interface{}, 0)
	arpactionparams = append(arpactionparams, ValueToBytes16(uint16(port)))

	arptbl := &Table{
		TableName:        "k8s_dp_control.arp_to_port_table",
		ActionName:       "k8s_dp_control.set_dest_vport",
		EntryCount:       1,
		KeyCount:         1,
		ActionParamCount: 1,
		KeyMatchType:     arpkeymatchtype,
		KeyName:          arpkeyNames,
		Key:              arpkeyparams,
		Action:           arpactionparams,
	}
	PrepareTable(cniarpmap, arptbl)

	err := ConfigureTable(ctx, p4RtC, P4w, tablenames, cniarpmap, actionnames, true)
	if err != nil {
		log.Errorf("failed to insert default gateway rule")
		return err
	}

	return nil
}

func InsertCniRules(ctx context.Context, p4RtC *client.Client, ep store.EndPoint,
	ifaceType InterfaceType) (store.EndPoint, error) {

	cniupdatemap := make(map[string][]UpdateTable)
	var err error
	P4w = GetP4Wrapper(Env)

	tablenames := []string{"k8s_dp_control.arp_to_port_table",
		"k8s_dp_control.pod_gateway_mac_mod_table",
		"k8s_dp_control.ipv4_to_port_table_tx",
		"k8s_dp_control.ipv4_to_port_table_rx",
		"k8s_dp_control.ipv4_to_port_table_tx_tcp",
		"k8s_dp_control.ipv4_to_port_table_tx_service"}

	actionnames := []string{"k8s_dp_control.set_dest_vport",
		"k8s_dp_control.update_src_dst_mac",
		"k8s_dp_control.set_dest_mac_vport",
		"k8s_dp_control.set_dest_vport",
		"k8s_dp_control.set_dest_mac_vport",
		"k8s_dp_control.set_dest_mac_vport"}

	if net.ParseIP(ep.PodIpAddress) == nil {
		err = fmt.Errorf("Invalid IP Address")
		return ep, err
	}
	fmt.Println("ep.PodIpAddress = ", ep.PodIpAddress)

	_, err = net.ParseMAC(ep.PodMacAddress)
	if err != nil {
		err = fmt.Errorf("Invalid MAC Address")
		return ep, err
	}
	fmt.Println("ep.PodMacAddress = ", ep.PodMacAddress)

	data := parseJson("cni.json")
	if data == nil {
		err = fmt.Errorf("Error while parsing Json file")
		return ep, err
	}

	var cni_offset uint32
	//cni_offset = 2000
	cni_offset = 700
	ep.ModPtr = cni_offset + uuidFactory.getUUID()

	key := make([]interface{}, 0)
	action := make([]interface{}, 0)

	fmt.Println("arp_to_port_table - ep.PodIpAddress = ", ep.PodIpAddress)
	key = append(key, Pack32BinaryIP4(ep.PodIpAddress))
	action = append(action, ValueToBytes16(uint16(ep.InterfaceID)))
	updateTables("k8s_dp_control.arp_to_port_table", data, cniupdatemap, key, action, 1)
	key = nil
	action = nil

	//pod_gateway_mac_mod_table
	key = append(key, ValueToBytes(ep.ModPtr))

	IP, netIp, err := net.ParseCIDR(types.DefaultRoute)
	if err != nil {
		log.Errorf("Failed to get IP from the default route cidr %s", types.DefaultRoute)
		//return
	}

	_ = netIp

	ip := IP.String()
	if len(ip) == 0 {
		log.Errorf("Empty value %s, cannot program default gateway", types.DefaultRoute)
		//return
	}
	fmt.Println("Default gateway ip = ", ip)
	ep1 := store.EndPoint{
		PodIpAddress: ip,
	}
	entry := ep1.GetFromStore()
	epEntry := entry.(store.EndPoint)
	smacbyte, _ := net.ParseMAC(epEntry.PodMacAddress)
	smac := []byte(smacbyte)
	action = append(action, smac)

	dmacbyte, _ := net.ParseMAC(ep.PodMacAddress)
	dmac := []byte(dmacbyte)
	action = append(action, dmac)
	updateTables("k8s_dp_control.pod_gateway_mac_mod_table", data, cniupdatemap, key, action, 1)
	key = nil
	action = nil

	//ipv4_to_port_table_tx
	fmt.Println("ipv4_to_port_table_tx - ep.PodIpAddress = ", ep.PodIpAddress)
	key = append(key, Pack32BinaryIP4(ep.PodIpAddress))
	action = append(action, ValueToBytes16(uint16(ep.InterfaceID)))
	action = append(action, ValueToBytes(ep.ModPtr))
	updateTables("k8s_dp_control.ipv4_to_port_table_tx", data, cniupdatemap, key, action, 1)
	key = nil
	action = nil

	//ipv4_to_port_table_rx
	fmt.Println("ipv4_to_port_table_rx - ep.PodIpAddress = ", ep.PodIpAddress)
	key = append(key, Pack32BinaryIP4(ep.PodIpAddress))
	action = append(action, ValueToBytes16(uint16(ep.InterfaceID)))
	updateTables("k8s_dp_control.ipv4_to_port_table_rx", data, cniupdatemap, key, action, 1)
	key = nil
	action = nil

	//ipv4_to_port_table_tx_tcp
	key = append(key, Pack32BinaryIP4(ep.PodIpAddress))
	action = append(action, ValueToBytes16(uint16(ep.InterfaceID)))
	action = append(action, ValueToBytes(ep.ModPtr))
	updateTables("k8s_dp_control.ipv4_to_port_table_tx_tcp", data, cniupdatemap, key, action, 1)
	key = nil
	action = nil

	//ipv4_to_port_table_tx_service
	key = append(key, Pack32BinaryIP4(ep.PodIpAddress))
	action = append(action, ValueToBytes16(uint16(ep.InterfaceID)))
	action = append(action, ValueToBytes(ep.ModPtr))
	updateTables("k8s_dp_control.ipv4_to_port_table_tx_service", data, cniupdatemap, key, action, 1)
	key = nil
	action = nil

	err = ConfigureTable(ctx, p4RtC, P4w, tablenames, cniupdatemap, actionnames, true)
	if err != nil {
		fmt.Println("failed to make entries to cni p4")
		return ep, err
	}

	return ep, nil
}

func DeleteCniRules(ctx context.Context, p4RtC *client.Client, ep store.EndPoint) error {

	cniupdatemap := make(map[string][]UpdateTable)
	var err error
	P4w = GetP4Wrapper(Env)

	tablenames := []string{"k8s_dp_control.arp_to_port_table",
		"k8s_dp_control.pod_gateway_mac_mod_table",
		"k8s_dp_control.ipv4_to_port_table_tx",
		"k8s_dp_control.ipv4_to_port_table_rx",
		"k8s_dp_control.ipv4_to_port_table_tx_tcp",
		"k8s_dp_control.ipv4_to_port_table_tx_service"}

	log.Infof("DeleteCniRules() Del request %s", ep.PodIpAddress)

	if net.ParseIP(ep.PodIpAddress) == nil {
		err = fmt.Errorf("Invalid IP Address")
		return err
	}

	data := parseJson("cni.json")
	if data == nil {
		err = fmt.Errorf("Error while parsing Json file")
		return err
	}

	key := make([]interface{}, 0)

	key = append(key, Pack32BinaryIP4(ep.PodIpAddress))
	updateTables("k8s_dp_control.arp_to_port_table", data, cniupdatemap, key, nil, 1)
	key = nil

	key = append(key, ValueToBytes(ep.ModPtr))
	updateTables("k8s_dp_control.pod_gateway_mac_mod_table", data, cniupdatemap, key, nil, 1)
	key = nil

	key = append(key, Pack32BinaryIP4(ep.PodIpAddress))
	updateTables("k8s_dp_control.ipv4_to_port_table_tx", data, cniupdatemap, key, nil, 1)
	key = nil

	key = append(key, Pack32BinaryIP4(ep.PodIpAddress))
	updateTables("k8s_dp_control.ipv4_to_port_table_rx", data, cniupdatemap, key, nil, 1)
	key = nil

	key = append(key, Pack32BinaryIP4(ep.PodIpAddress))
	updateTables("k8s_dp_control.ipv4_to_port_table_tx_tcp", data, cniupdatemap, key, nil, 1)
	key = nil

	key = append(key, Pack32BinaryIP4(ep.PodIpAddress))
	updateTables("k8s_dp_control.ipv4_to_port_table_tx_service", data, cniupdatemap, key, nil, 1)
	key = nil

	err = ConfigureTable(ctx, p4RtC, P4w, tablenames, cniupdatemap, nil, false)
	if err != nil {
		fmt.Println("failed to delete entries to cni p4")
		return err
	}

	return nil
}
