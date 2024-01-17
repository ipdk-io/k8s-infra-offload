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
	"github.com/ipdk-io/k8s-infra-offload/pkg/types"

	//p4_v1 "github.com/p4lang/p4runtime/go/p4/v1"
	"net"

	log "github.com/sirupsen/logrus"
)

var (
	service_table_names = []string{"k8s_dp_control.ipv4_to_port_table_tx_tcp",
		"k8s_dp_control.ipv4_to_port_table_tx",
		"k8s_dp_control.write_dest_ip_table",
		"k8s_dp_control.write_source_ip_table",
		"k8s_dp_control.rx_src_ip",
		"k8s_dp_control.tx_balance"}

	service_action_names = []string{"k8s_dp_control.set_vip_flag_tcp",
		"k8s_dp_control.set_vip_flag",
		"k8s_dp_control.update_dst_ip_mac",
		"k8s_dp_control.update_src_ip_mac",
		"k8s_dp_control.set_source_ip",
		"k8s_dp_control.set_default_lb_dest"}
)

// To track unique combination of service IP and service protocol.
var flagMap = make(map[string]bool)

func ServiceFlowPacketOptions(ctx context.Context, p4RtC *client.Client,
	flags [][]byte, action InterfaceType) error {
	P4w = GetP4Wrapper(Env)

	switch action {
	case Insert:
		for i := 1; i <= 12; i++ {
			entryAdd := P4w.NewTableEntry(
				p4RtC,
				"k8s_dp_control.service_flow_packet_options",
				map[string]client.MatchInterface{
					"istd.direction": &client.ExactMatch{
						Value: ValueToBytes8(uint8(1)),
					},
					"hdrs.tcp.ack": &client.ExactMatch{
						Value: converttobytestream(flags[i][0]),
					},
					"hdrs.tcp.rst": &client.ExactMatch{
						Value: converttobytestream(flags[i][1]),
					},
					"hdrs.tcp.syn": &client.ExactMatch{
						Value: converttobytestream(flags[i][2]),
					},
					"hdrs.tcp.fin": &client.ExactMatch{
						Value: converttobytestream(flags[i][3]),
					},
				},
				P4w.NewTableActionDirect(p4RtC, "k8s_dp_control.tcp_fin_or_rst_packet",
					nil,
				),
				nil,
			)
			if err := P4w.InsertTableEntry(ctx, p4RtC, entryAdd); err != nil {
				log.Errorf("Cannot insert entry into 'service_flow_packet_options': %v", err)
				return err
			}
		}
		for i := 13; i <= 15; i++ {
			entryAdd := P4w.NewTableEntry(
				p4RtC,
				"k8s_dp_control.service_flow_packet_options",
				map[string]client.MatchInterface{
					"istd.direction": &client.ExactMatch{
						Value: ValueToBytes8(uint8(1)),
					},
					"hdrs.tcp.ack": &client.ExactMatch{
						Value: converttobytestream(flags[i][0]),
					},
					"hdrs.tcp.rst": &client.ExactMatch{
						Value: converttobytestream(flags[i][1]),
					},
					"hdrs.tcp.syn": &client.ExactMatch{
						Value: converttobytestream(flags[i][2]), //care -syn
					},
					"hdrs.tcp.fin": &client.ExactMatch{
						Value: converttobytestream(flags[i][3]),
					},
				},
				P4w.NewTableActionDirect(p4RtC, "k8s_dp_control.tcp_other_packets",
					nil,
				),
				nil,
			)
			if err := P4w.InsertTableEntry(ctx, p4RtC, entryAdd); err != nil {
				log.Errorf("Cannot insert entry into 'service_flow_packet_options': %v", err)
				return err
			}
		}

		entryAdd := P4w.NewTableEntry(
			p4RtC,
			"k8s_dp_control.service_flow_packet_options",
			map[string]client.MatchInterface{
				"istd.direction": &client.ExactMatch{
					Value: ValueToBytes8(uint8(1)),
				},
				"hdrs.tcp.ack": &client.ExactMatch{
					Value: converttobytestream(flags[0][0]),
				},
				"hdrs.tcp.rst": &client.ExactMatch{
					Value: converttobytestream(flags[0][1]),
				},
				"hdrs.tcp.syn": &client.ExactMatch{
					Value: converttobytestream(flags[0][2]), //care -syn
				},
				"hdrs.tcp.fin": &client.ExactMatch{
					Value: converttobytestream(flags[0][3]),
				},
			},
			P4w.NewTableActionDirect(p4RtC, "k8s_dp_control.tcp_syn_packet",
				nil,
			),
			nil,
		)
		if err := P4w.InsertTableEntry(ctx, p4RtC, entryAdd); err != nil {
			log.Errorf("Cannot insert entry into 'service_flow_packet_options': %v", err)
			return err
		}

	case Delete:
		for i := 0; i <= 15; i++ {
			entryDel := P4w.NewTableEntry(
				p4RtC,
				"k8s_dp_control.service_flow_packet_options",
				map[string]client.MatchInterface{
					"istd.direction": &client.ExactMatch{
						Value: ValueToBytes8(uint8(1)),
					},
					"hdrs.tcp.ack": &client.ExactMatch{
						Value: converttobytestream(flags[i][0]),
					},
					"hdrs.tcp.rst": &client.ExactMatch{
						Value: converttobytestream(flags[i][1]),
					},
					"hdrs.tcp.syn": &client.ExactMatch{
						Value: converttobytestream(flags[i][2]),
					},
					"hdrs.tcp.fin": &client.ExactMatch{
						Value: converttobytestream(flags[i][3]),
					},
				},
				nil,
				nil,
			)
			if err := P4w.DeleteTableEntry(ctx, p4RtC, entryDel); err != nil {
				log.Errorf("Failed to delete entry from 'service_flow_packet_options': %v", err)
				return err
			}
		}

	case Update:
		return nil

	default:
		log.Warnf("Invalid action %v", action)
		err := fmt.Errorf("Invalid action %v", action)
		return err
	}

	return nil
}

func concatOldEntries(modblobPtrDNAT [][]byte, oldModblobPtrDNAT [][]byte, oldIpAddrs []string, InterfaceIDs [][]byte) ([][]byte, [][]byte) {

	oldInterfaceIDs := make([][]byte, 0)
	for i := 0; i < len(oldIpAddrs); i++ {
		ep := store.EndPoint{
			PodIpAddress: oldIpAddrs[i],
		}
		entry := ep.GetFromStore()
		if entry != nil {
			epEntry := entry.(store.EndPoint)
			oldInterfaceIDs = append(oldInterfaceIDs, ValueToBytes16(uint16(epEntry.InterfaceID)))
		}
	}

	InterfaceIDs = append(InterfaceIDs, oldInterfaceIDs...)
	modblobPtrDNAT = append(modblobPtrDNAT, oldModblobPtrDNAT...)

	return modblobPtrDNAT, InterfaceIDs
}

func InsertServiceRules(ctx context.Context, p4RtC *client.Client,
	podIpAddr []string, portID []uint16, s store.Service,
	update bool, replay bool) (err error, service store.Service) {
	var actn InterfaceType
	var epNum uint32
	var groupID uint32

	svcmap := make(map[string][]UpdateTable)
	key := make([]interface{}, 0)
	action := make([]interface{}, 0)

	modblobptrdnatbyte := make([][]byte, 0)
	oldmodblobptrdnatbyte := make([][]byte, 0)
	oldIpAddrs := make([]string, 0)

	podipByte := make([][]byte, 0)
	portIDByte := make([][]byte, 0)
	macByte := make([][]byte, 0)
	InterfaceIDbyte := make([][]byte, 0)

	service = s

	if len(podIpAddr) == 0 {
		err := fmt.Errorf("No Endpoints to program")
		return err, store.Service{}
	}

	log.Infof("Inserting to service tables")

	if replay {
		actn = Insert
		groupID = service.GroupID
		epNum = 0
	} else if update {
		actn = Update
		groupID = service.GroupID
		epNum = service.NumEndPoints

		for _, value := range s.ServiceEndPoint {
			oldIpAddrs = append(oldIpAddrs, value.IpAddress)
			oldmodblobptrdnatbyte = append(oldmodblobptrdnatbyte, ValueToBytes(value.ModBlobPtrDNAT))
		}
	} else {
		actn = Insert
		groupID = uuidFactory.getUUID()
		service.GroupID = groupID
		epNum = 0
	}

	if net.ParseIP(s.ClusterIp) == nil {
		err := fmt.Errorf("Invalid cluster IP: %s", s.ClusterIp)
		return err, store.Service{}
	}

	for i := 0; i < len(podIpAddr); i, epNum = i+1, epNum+1 {
		if net.ParseIP(podIpAddr[i]) == nil {
			err := fmt.Errorf("Invalid IP Address: %s", podIpAddr[i])
			return err, store.Service{}
		}
		podipByte = append(podipByte, Pack32BinaryIP4(podIpAddr[i]))
		portIDByte = append(portIDByte, ValueToBytes16(uint16(portID[i]))) //L4 port

		id := uint32((groupID << 4) | ((epNum + 1) & 0xF))
		modblobptrdnatbyte = append(modblobptrdnatbyte, ValueToBytes(id))

		log.Debugf("modblobptrdnatbyte: %d, pod ip: %s, portID: %d",
			modblobptrdnatbyte[i], podIpAddr[i], portID[i])

		serviceEp := store.ServiceEndPoint{
			IpAddress:      podIpAddr[i],
			Port:           uint16(portID[i]), //L4 port
			ModBlobPtrDNAT: id,
		}
		service.ServiceEndPoint[podIpAddr[i]] = serviceEp

		ep := store.EndPoint{
			PodIpAddress: podIpAddr[i],
		}
		entry := ep.GetFromStore()
		if entry != nil {
			epEntry := entry.(store.EndPoint)

			podmac, err := net.ParseMAC(epEntry.PodMacAddress)
			if err != nil {
				err = fmt.Errorf("Invalid MAC Address")
				return err, store.Service{}
			}
			macByte = append(macByte, podmac)

			InterfaceIDbyte = append(InterfaceIDbyte, ValueToBytes16(uint16(epEntry.InterfaceID))) //L2 forwarding port
		} else {
			err := fmt.Errorf("Endpoint %s not found, cannot program service %s",
				ep.PodIpAddress, service.ClusterIp)
			return err, store.Service{}
		}

	}
	service.NumEndPoints = epNum

	log.Debugf("group id: %d, service ip: %s, service mac: %s, service port: %d, endpoints: %d",
		groupID, service.ClusterIp, service.MacAddr, service.Port, service.NumEndPoints)

	data := parseJson("service.json")
	if data == nil {
		err = fmt.Errorf("Error while parsing Json file")
		return err, service
	}

	//inserting forwarding rules for service IP
	IP, netIp, err := net.ParseCIDR(types.DefaultRoute)
	if err != nil {
		log.Errorf("Failed to get IP from the default route cidr %s", types.DefaultRoute)
		return
	}

	_ = netIp

	ip := IP.String()
	if len(ip) == 0 {
		log.Errorf("Empty value %s", types.DefaultRoute)
		return
	}

	ep := store.EndPoint{
		PodIpAddress: ip,
	}
	entry := ep.GetFromStore()
	if entry == nil {
		err = fmt.Errorf("entry does not exist for DefaultRoute")
		return
	}
	epEntry := entry.(store.EndPoint)
	smacbyte, err := net.ParseMAC(epEntry.PodMacAddress)
	if err != nil {
		err = fmt.Errorf("Invalid MAC Address for DefaultRoute")
		return
	}
	smac := []byte(smacbyte)

	// The set_vip_flag or set_vip_flag_tcp action is invoked only once for each unique combination of service IP and service protocol.
	vip_flag_key := service.ClusterIp + service.Proto
	val, exists := flagMap[vip_flag_key]
	if !exists || val == false {
		key = append(key, Pack32BinaryIP4(service.ClusterIp))
		if service.Proto == "TCP" {
			updateTables("k8s_dp_control.ipv4_to_port_table_tx_tcp", data, svcmap, key, nil, 1)
		} else {
			updateTables("k8s_dp_control.ipv4_to_port_table_tx", data, svcmap, key, nil, 1)
		}
		flagMap[vip_flag_key] = true
		resetSlices(&key, &action)
	} else {
		log.Debugf("vip flag already exists, skipping")
	}

	//inserting service tables

	//write_dest_ip_table
	key = append(key, modblobptrdnatbyte)
	action = append(action, smac)
	action = append(action, macByte)
	action = append(action, podipByte)
	action = append(action, portIDByte)
	updateTables("k8s_dp_control.write_dest_ip_table", data, svcmap, key, action, len(podIpAddr))
	resetSlices(&key, &action)

	log.Debugf("Inserted into table WriteDestIpTable, pod ip addrs: %v, port id: %v, mod blob ptrs: %v",
		podipByte, InterfaceIDbyte, modblobptrdnatbyte)

	//write_source_ip_table
	if actn != Update {
		key = append(key, ValueToBytes(groupID))
		action = append(action, smac)
		action = append(action, Pack32BinaryIP4(service.ClusterIp))
		action = append(action, ValueToBytes16(uint16(service.Port)))
		updateTables("k8s_dp_control.write_source_ip_table", data, svcmap, key, action, 1)
		resetSlices(&key, &action)

		log.Debugf("Inserted into table WriteSourceIpTable, group id: %d, service ip: %s, service port: %d",
			groupID, service.ClusterIp, uint16(service.Port))
	}

	//rx_src_ip
	key = append(key, podipByte)
	if service.Proto == "TCP" {
		key = append(key, ValueToBytes8(uint8(PROTO_TCP)))
	} else {
		key = append(key, ValueToBytes8(uint8(PROTO_UDP)))
	}
	key = append(key, portIDByte)
	action = append(action, ValueToBytes(groupID))
	updateTables("k8s_dp_control.rx_src_ip", data, svcmap, key, action, len(podIpAddr))
	resetSlices(&key, &action)
	log.Debugf("Inserted into table RxSrcIpTable, group id: %d, podipByte: %v, portIDByte: %v",
		groupID, podipByte, portIDByte)

	if actn == Update {
		modblobptrdnatbyte, InterfaceIDbyte = concatOldEntries(modblobptrdnatbyte, oldmodblobptrdnatbyte, oldIpAddrs, InterfaceIDbyte)
		log.Debugf("Update tx_balance table, modblobptrdnatbyte: %v, InterfaceIDbyte: %v",
			modblobptrdnatbyte, InterfaceIDbyte)
	}
	//tx_balance
	key = append(key, Pack32BinaryIP4(service.ClusterIp))
	if service.Proto == "TCP" {
		key = append(key, ValueToBytes8(uint8(PROTO_TCP)))
	} else {
		key = append(key, ValueToBytes8(uint8(PROTO_UDP)))
	}
	key = append(key, ValueToBytes16(uint16(service.Port))) //L4 port

	for i := 0; i < 64; i++ {
		key = append(key, ValueToBytes8(uint8(i)))

		index := i % int(epNum)
		action = append(action, InterfaceIDbyte[index])
		action = append(action, modblobptrdnatbyte[index])

		updateTables("k8s_dp_control.tx_balance", data, svcmap, key, action, 1)

		//Remove last element from key
		key = key[:len(key)-1]
		action = nil
	}
	resetSlices(&key, &action)
	log.Debugf("Inserted into the table TxBalance, service ip: %s, service port: %d",
		service.ClusterIp, uint16(service.Port))

	err = ConfigureTable(ctx, p4RtC, P4w, service_table_names, svcmap, service_action_names, true)
	if err != nil {
		fmt.Println("failed to make entries to service p4")
		return err, service
	}

	return nil, service
}

func DeleteServiceRules(ctx context.Context, p4RtC *client.Client,
	s store.Service) error {
	var err error
	var groupID uint32
	var service store.Service

	podipByte := make([][]byte, 0)
	portIDByte := make([][]byte, 0)
	modblobptrdnatbyte := make([][]byte, 0)

	svcmap := make(map[string][]UpdateTable)
	key := make([]interface{}, 0)

	log.Infof("Deleting from service tables")

	data := parseJson("service.json")
	if data == nil {
		err = fmt.Errorf("Error while parsing Json file")
		return err
	}

	res := s.GetFromStore()
	if res == nil {
		err = fmt.Errorf("No GroupID found")
		return err
	}

	service = res.(store.Service)
	groupID = service.GroupID
	NumEp := int(service.NumEndPoints)

	for _, ep := range service.ServiceEndPoint {
		podipByte = append(podipByte, Pack32BinaryIP4(ep.IpAddress))
		portIDByte = append(portIDByte, ValueToBytes16(uint16(ep.Port)))
		modblobptrdnatbyte = append(modblobptrdnatbyte, ValueToBytes(ep.ModBlobPtrDNAT))
		log.Infof("modblobPtrDNAT: %d pod ip: %s, portID: %d",
			ep.ModBlobPtrDNAT, ep.IpAddress, ep.Port)
	}

	// Deletion of the set_vip_flag or set_vip_flag_tcp action is executed once for each unique combination of service IP and service protocol.
	vip_flag_key := service.ClusterIp + service.Proto
	val, exists := flagMap[vip_flag_key]
	if exists && val == true {
		key = append(key, Pack32BinaryIP4(service.ClusterIp))
		if service.Proto == "TCP" {
			updateTables("k8s_dp_control.ipv4_to_port_table_tx_tcp", data, svcmap, key, nil, 1)
			log.Debugf("Deleting from table ipv4_to_port_table_tx_tcp, service.ClusterIp: %s", service.ClusterIp)
		} else {
			updateTables("k8s_dp_control.ipv4_to_port_table_tx", data, svcmap, key, nil, 1)
			log.Debugf("Deleting from table ipv4_to_port_table_tx, service.ClusterIp: %s", service.ClusterIp)
		}
		flagMap[vip_flag_key] = false
		resetSlices(&key, nil)
	}

	//write_dest_ip_table
	log.Debugf("Deleting from table WriteDestIpTable, mod blob ptrs: %v", modblobptrdnatbyte)
	key = append(key, modblobptrdnatbyte)
	updateTables("k8s_dp_control.write_dest_ip_table", data, svcmap, key, nil, NumEp)
	resetSlices(&key, nil)

	//write_source_ip_table
	log.Debugf("Deleting from table WriteSourceIpTable, group id: %d", groupID)
	key = append(key, ValueToBytes(groupID))
	updateTables("k8s_dp_control.write_source_ip_table", data, svcmap, key, nil, 1)
	resetSlices(&key, nil)

	//rx_src_ip
	log.Debugf("Deleting from table RxSrcIpTable, NumEp: %d, service ip: %s, service port: %d",
		NumEp, service.ClusterIp, uint16(service.Port))
	key = append(key, podipByte)
	if service.Proto == "TCP" {
		key = append(key, ValueToBytes8(uint8(PROTO_TCP)))
	} else {
		key = append(key, ValueToBytes8(uint8(PROTO_UDP)))
	}
	key = append(key, portIDByte)
	updateTables("k8s_dp_control.rx_src_ip", data, svcmap, key, nil, NumEp)
	resetSlices(&key, nil)

	//tx_balance
	log.Debugf("Deleting from table TxBalanceTable, service ip: %s, service port: %d, service.Proto: %s",
		service.ClusterIp, uint16(service.Port), service.Proto)

	key = append(key, Pack32BinaryIP4(service.ClusterIp))
	if service.Proto == "TCP" {
		key = append(key, ValueToBytes8(uint8(PROTO_TCP)))
	} else {
		key = append(key, ValueToBytes8(uint8(PROTO_UDP)))
	}
	key = append(key, ValueToBytes16(uint16(service.Port)))

	for i := 0; i < 64; i++ {
		key = append(key, ValueToBytes8(uint8(i)))

		updateTables("k8s_dp_control.tx_balance", data, svcmap, key, nil, 1)
		key = key[:len(key)-1]
	}
	resetSlices(&key, nil)

	err = ConfigureTable(ctx, p4RtC, P4w, service_table_names, svcmap, nil, false)
	if err != nil {
		fmt.Println("failed to delete entries")
		return err
	}

	return nil
}
