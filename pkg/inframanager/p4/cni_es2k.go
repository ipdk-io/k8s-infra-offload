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

var (
	cni_table_names = []string{"k8s_dp_control.arp_to_port_table",
		"k8s_dp_control.pod_gateway_mac_mod_table",
		"k8s_dp_control.ipv4_to_port_table_tx",
		"k8s_dp_control.ipv4_to_port_table_rx",
		"k8s_dp_control.ipv4_to_port_table_tx_tcp",
		"k8s_dp_control.ipv4_to_port_table_tx_service"}

	cni_action_names = []string{"k8s_dp_control.set_dest_vport",
		"k8s_dp_control.update_src_dst_mac",
		"k8s_dp_control.set_dest_mac_vport",
		"k8s_dp_control.set_dest_vport",
		"k8s_dp_control.set_dest_mac_vport",
		"k8s_dp_control.set_dest_mac_vport"}
)

func ArptToPortTable(ctx context.Context, p4RtC *client.Client, arpTpa string, port uint32, flag bool) error {
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

	err := ConfigureTable(ctx, p4RtC, P4w, tablenames, cniarpmap, actionnames, flag)
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

	if net.ParseIP(ep.PodIpAddress) == nil {
		err = fmt.Errorf("Invalid IP Address")
		return ep, err
	}

	_, err = net.ParseMAC(ep.PodMacAddress)
	if err != nil {
		err = fmt.Errorf("Invalid MAC Address")
		return ep, err
	}

	data := parseJson("cni.json")
	if data == nil {
		err = fmt.Errorf("Error while parsing Json file")
		return ep, err
	}

	//To avoid overlapping with service modblob
	var cni_modblob_offset uint32
	cni_modblob_offset = 700
	ep.ModPtr = cni_modblob_offset + uuidFactory.getUUID()

	key := make([]interface{}, 0)
	action := make([]interface{}, 0)

	key = append(key, Pack32BinaryIP4(ep.PodIpAddress))
	action = append(action, ValueToBytes16(uint16(ep.InterfaceID)))
	updateTables("k8s_dp_control.arp_to_port_table", data, cniupdatemap, key, action, 1)
	resetSlices(&key, &action)

	//pod_gateway_mac_mod_table
	key = append(key, ValueToBytes(ep.ModPtr))

	IP, netIp, err := net.ParseCIDR(types.DefaultRoute)
	if err != nil {
		log.Errorf("Failed to get IP from the default route cidr %s", types.DefaultRoute)
		return ep, err
	}

	_ = netIp

	ip := IP.String()
	if len(ip) == 0 {
		log.Errorf("Empty value %s, cannot program default gateway", types.DefaultRoute)
		return ep, err
	}
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
	resetSlices(&key, &action)

	//ipv4_to_port_table_tx
	key = append(key, Pack32BinaryIP4(ep.PodIpAddress))
	action = append(action, ValueToBytes16(uint16(ep.InterfaceID)))
	action = append(action, ValueToBytes(ep.ModPtr))
	updateTables("k8s_dp_control.ipv4_to_port_table_tx", data, cniupdatemap, key, action, 1)
	resetSlices(&key, &action)

	//ipv4_to_port_table_rx
	key = append(key, Pack32BinaryIP4(ep.PodIpAddress))
	action = append(action, ValueToBytes16(uint16(ep.InterfaceID)))
	updateTables("k8s_dp_control.ipv4_to_port_table_rx", data, cniupdatemap, key, action, 1)
	resetSlices(&key, &action)

	//ipv4_to_port_table_tx_tcp
	key = append(key, Pack32BinaryIP4(ep.PodIpAddress))
	action = append(action, ValueToBytes16(uint16(ep.InterfaceID)))
	action = append(action, ValueToBytes(ep.ModPtr))
	updateTables("k8s_dp_control.ipv4_to_port_table_tx_tcp", data, cniupdatemap, key, action, 1)
	resetSlices(&key, &action)

	//ipv4_to_port_table_tx_service
	key = append(key, Pack32BinaryIP4(ep.PodIpAddress))
	action = append(action, ValueToBytes16(uint16(ep.InterfaceID)))
	action = append(action, ValueToBytes(ep.ModPtr))
	updateTables("k8s_dp_control.ipv4_to_port_table_tx_service", data, cniupdatemap, key, action, 1)
	resetSlices(&key, &action)

	err = ConfigureTable(ctx, p4RtC, P4w, cni_table_names, cniupdatemap, cni_action_names, true)
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

	log.Infof("DeleteCniRules Del request %s", ep.PodIpAddress)

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
	resetSlices(&key, nil)

	key = append(key, ValueToBytes(ep.ModPtr))
	updateTables("k8s_dp_control.pod_gateway_mac_mod_table", data, cniupdatemap, key, nil, 1)
	resetSlices(&key, nil)

	key = append(key, Pack32BinaryIP4(ep.PodIpAddress))
	updateTables("k8s_dp_control.ipv4_to_port_table_tx", data, cniupdatemap, key, nil, 1)
	resetSlices(&key, nil)
	key = nil

	key = append(key, Pack32BinaryIP4(ep.PodIpAddress))
	updateTables("k8s_dp_control.ipv4_to_port_table_rx", data, cniupdatemap, key, nil, 1)
	resetSlices(&key, nil)

	key = append(key, Pack32BinaryIP4(ep.PodIpAddress))
	updateTables("k8s_dp_control.ipv4_to_port_table_tx_tcp", data, cniupdatemap, key, nil, 1)
	resetSlices(&key, nil)

	key = append(key, Pack32BinaryIP4(ep.PodIpAddress))
	updateTables("k8s_dp_control.ipv4_to_port_table_tx_service", data, cniupdatemap, key, nil, 1)
	resetSlices(&key, nil)

	err = ConfigureTable(ctx, p4RtC, P4w, cni_table_names, cniupdatemap, nil, false)
	if err != nil {
		fmt.Println("failed to delete entries to cni p4")
		return err
	}

	return nil
}
