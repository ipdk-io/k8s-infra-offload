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
	p4_v1 "github.com/p4lang/p4runtime/go/p4/v1"
	log "github.com/sirupsen/logrus"
	"net"
)

func WriteDestIpTable(ctx context.Context, p4RtC *client.Client,
	podIpAddr []string, portID []uint16, modBlobPtrDnat []uint32,
	action InterfaceType) error {
	switch action {
	case Insert, Update:
		for i := 0; i < len(modBlobPtrDnat); i++ {
			if net.ParseIP(podIpAddr[i]) == nil {
				err := fmt.Errorf("Invalid IP address: %s", podIpAddr[i])
				return err
			}

			entryAdd := p4RtC.NewTableEntry(
				"k8s_dp_control.write_dest_ip_table",
				map[string]client.MatchInterface{
					"meta.mod_blob_ptr_dnat": &client.ExactMatch{
						Value: valueToBytes(modBlobPtrDnat[i]),
					},
				},
				p4RtC.NewTableActionDirect("k8s_dp_control.update_dst_ip",
					[][]byte{Pack32BinaryIP4(podIpAddr[i]),
						valueToBytes16(portID[i])}),
				nil,
			)
			if err := p4RtC.InsertTableEntry(ctx, entryAdd); err != nil {
				log.Errorf("Cannot insert entry into 'write_dest_ip_table': %v", err)
				return err
			}
		}
	case Delete:
		for i := 0; i < len(modBlobPtrDnat); i++ {
			entryDelete := p4RtC.NewTableEntry(
				"k8s_dp_control.write_dest_ip_table",
				map[string]client.MatchInterface{
					"meta.mod_blob_ptr_dnat": &client.ExactMatch{
						Value: valueToBytes(modBlobPtrDnat[i]),
					},
				},
				nil,
				nil,
			)
			if err := p4RtC.DeleteTableEntry(ctx, entryDelete); err != nil {
				log.Errorf("Cannot delete entry from 'write_dest_ip_table': %v", err)
				return err
			}
		}
	default:
		log.Warnf("Invalid action %v", action)
		err := fmt.Errorf("Invalid action %v", action)
		return err
	}

	return nil
}

func AsSl3TcpTable(ctx context.Context, p4RtC *client.Client,
	memberID []uint32, modBlobPtr []uint32,
	groupID uint32, action InterfaceType) error {
	var err error
	var memberList []*p4_v1.ActionProfileGroup_Member

	for i := 0; i < len(memberID); i++ {
		member := &p4_v1.ActionProfileGroup_Member{
			MemberId: memberID[i],
		}
		memberList = append(memberList, member)

	}

	entryGroupTcp := p4RtC.NewActionProfileGroup(
		"k8s_dp_control.as_sl3_tcp",
		groupID,
		memberList,
		int32(128),
	)

	if action == Delete {
		if err = p4RtC.DeleteActionProfileGroup(ctx, entryGroupTcp); err != nil {
			log.Errorf("Cannot delete group entry from 'as_sl3_tcp table': %v", err)
			return err
		}
	}

	for i := 0; i < len(memberID); i++ {
		entryMemberTcp := p4RtC.NewActionProfileMember(
			"k8s_dp_control.as_sl3_tcp",
			memberID[i],
			"k8s_dp_control.set_default_lb_dest",
			[][]byte{valueToBytes(modBlobPtr[i])},
		)
		switch action {
		case Insert, Update:
			if err = p4RtC.InsertActionProfileMember(ctx, entryMemberTcp); err != nil {
				log.Errorf("Cannot insert member entry into 'as_sl3_tcp table': %v", err)
				return err
			}
		case Delete:
			if err = p4RtC.DeleteActionProfileMember(ctx, entryMemberTcp); err != nil {
				log.Errorf("Cannot delete member entry from 'as_sl3_tcp table': %v", err)
				return err
			}
		default:
			log.Warnf("Invalid action %v", action)
			err := fmt.Errorf("Invalid action %v", action)
			return err
		}
	}

	switch action {
	case Insert:
		if err = p4RtC.InsertActionProfileGroup(ctx, entryGroupTcp); err != nil {
			log.Errorf("Cannot insert group entry into 'as_sl3_tcp table': %v", err)
			return err
		}
	case Update:
		if err = p4RtC.ModifyActionProfileGroup(ctx, entryGroupTcp); err != nil {
			log.Errorf("Cannot update group entry into 'as_sl3_tcp table': %v", err)
			return err
		}
	case Delete:
	default:
		log.Warnf("Invalid action %v", action)
		err := fmt.Errorf("Invalid action %v", action)
		return err
	}

	return nil
}

func AsSl3UdpTable(ctx context.Context, p4RtC *client.Client,
	memberID []uint32, modBlobPtr []uint32,
	groupID uint32, action InterfaceType) error {
	var err error
	var memberList []*p4_v1.ActionProfileGroup_Member

	for i := 0; i < len(memberID); i++ {
		member := &p4_v1.ActionProfileGroup_Member{
			MemberId: memberID[i],
		}
		memberList = append(memberList, member)
	}

	entryGroupUdp := p4RtC.NewActionProfileGroup(
		"k8s_dp_control.as_sl3_udp",
		groupID,
		memberList,
		int32(128),
	)

	if action == Delete {
		if err = p4RtC.DeleteActionProfileGroup(ctx, entryGroupUdp); err != nil {
			log.Errorf("Cannot delete group entry from 'as_sl3_udp table': %v", err)
			return err
		}
	}

	for i := 0; i < len(memberID); i++ {
		entryMemberUdp := p4RtC.NewActionProfileMember(
			"k8s_dp_control.as_sl3_udp",
			memberID[i],
			"k8s_dp_control.set_default_lb_dest",
			[][]byte{valueToBytes(modBlobPtr[i])},
		)
		switch action {
		case Insert, Update:
			if err = p4RtC.InsertActionProfileMember(ctx, entryMemberUdp); err != nil {
				log.Errorf("Cannot insert member entry into 'as_sl3_udp table': %v", err)
				return err
			}
		case Delete:
			if err = p4RtC.DeleteActionProfileMember(ctx, entryMemberUdp); err != nil {
				log.Errorf("Cannot delete member entry from 'as_sl3_udp table': %v", err)
				return err
			}
		default:
			log.Warnf("Invalid action %v", action)
			err := fmt.Errorf("Invalid action %v", action)
			return err
		}
	}

	switch action {
	case Insert:
		if err = p4RtC.InsertActionProfileGroup(ctx, entryGroupUdp); err != nil {
			log.Errorf("Cannot insert group entry into 'as_sl3_udp table': %v", err)
			return err
		}
	case Update:
		if err = p4RtC.ModifyActionProfileGroup(ctx, entryGroupUdp); err != nil {
			log.Errorf("Cannot insert group entry into 'as_sl3_udp table': %v", err)
			return err
		}
	case Delete:
	default:
		log.Warnf("Invalid action %v", action)
		err := fmt.Errorf("Invalid action %v", action)
		return err
	}

	return nil
}

func TxBalanceTcpTable(ctx context.Context, p4RtC *client.Client,
	serviceIpAddr string, servicePort uint16,
	groupID uint32, action InterfaceType) error {
	if net.ParseIP(serviceIpAddr) == nil {
		err := fmt.Errorf("Invalid IP Address: %s", serviceIpAddr)
		return err
	}

	mfs := map[string]client.MatchInterface{
		"hdr.ipv4.dst_addr": &client.ExactMatch{
			Value: Pack32BinaryIP4(serviceIpAddr),
		},
		"hdr.tcp.dst_port": &client.ExactMatch{
			Value: valueToBytes16(servicePort),
		},
	}
	entryTcp := p4RtC.NewTableEntry(
		"k8s_dp_control.tx_balance_tcp",
		mfs,
		p4RtC.NewTableActionGroup(groupID),
		nil,
	)
	switch action {
	case Insert:
		if err := p4RtC.InsertTableEntry(ctx, entryTcp); err != nil {
			log.Errorf("Cannot insert entry into 'tx_balance_tcp table': %v", err)
			return err
		}
	case Delete:
		if err := p4RtC.DeleteTableEntry(ctx, entryTcp); err != nil {
			log.Errorf("Cannot delete entry from 'tx_balance_tcp table': %v", err)
			return err
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

func TxBalanceUdpTable(ctx context.Context, p4RtC *client.Client,
	serviceIpAddr string, servicePort uint16,
	groupID uint32, action InterfaceType) error {
	if net.ParseIP(serviceIpAddr) == nil {
		err := fmt.Errorf("Invalid IP Address: %s", serviceIpAddr)
		return err
	}

	mfs := map[string]client.MatchInterface{
		"hdr.ipv4.dst_addr": &client.ExactMatch{
			Value: Pack32BinaryIP4(serviceIpAddr),
		},
		"hdr.udp.dst_port": &client.ExactMatch{
			Value: valueToBytes16(servicePort),
		},
	}
	entryUdp := p4RtC.NewTableEntry(
		"k8s_dp_control.tx_balance_udp",
		mfs,
		p4RtC.NewTableActionGroup(groupID),
		nil,
	)
	switch action {
	case Insert:
		if err := p4RtC.InsertTableEntry(ctx, entryUdp); err != nil {
			log.Errorf("Cannot insert entry into 'tx_balance_udp table': %v", err)
			return err
		}
	case Delete:
		if err := p4RtC.DeleteTableEntry(ctx, entryUdp); err != nil {
			log.Errorf("Cannot delete entry from 'tx_balance_udp table': %v", err)
			return err
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

func WriteSourceIpTable(ctx context.Context, p4RtC *client.Client,
	ModBlobPtrSnat uint32, serviceIpAddr string, servicePort uint16,
	action InterfaceType) error {
	switch action {
	case Insert:
		if net.ParseIP(serviceIpAddr) == nil {
			err := fmt.Errorf("Invalid IP Address: %s", serviceIpAddr)
			return err
		}

		entryAdd := p4RtC.NewTableEntry(
			"k8s_dp_control.write_source_ip_table",
			map[string]client.MatchInterface{
				"meta.mod_blob_ptr_snat": &client.ExactMatch{
					Value: valueToBytes(ModBlobPtrSnat),
				},
			},
			p4RtC.NewTableActionDirect("k8s_dp_control.update_src_ip",
				[][]byte{Pack32BinaryIP4(serviceIpAddr),
					valueToBytes16(servicePort)}),
			nil,
		)
		if err := p4RtC.InsertTableEntry(ctx, entryAdd); err != nil {
			log.Errorf("Cannot insert entry into 'write_source_ip_table table': %v", err)
			return err
		}
	case Delete:
		entryDelete := p4RtC.NewTableEntry(
			"k8s_dp_control.write_source_ip_table",
			map[string]client.MatchInterface{
				"meta.mod_blob_ptr_snat": &client.ExactMatch{
					Value: valueToBytes(ModBlobPtrSnat),
				},
			},
			nil,
			nil,
		)
		if err := p4RtC.DeleteTableEntry(ctx, entryDelete); err != nil {
			log.Errorf("Cannot delete entry from 'write_source_ip_table table': %v", err)
			return err
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

func SetMetaTcpTable(ctx context.Context, p4RtC *client.Client,
	podIpAddr []string, portID []uint16,
	ModBlobPtrSnat uint32, action InterfaceType) error {
	switch action {
	case Insert, Update:
		for i := 0; i < len(podIpAddr); i++ {
			if net.ParseIP(podIpAddr[i]) == nil {
				err := fmt.Errorf("Invalid IP Address: %s", podIpAddr[i])
				return err
			}

			entryAdd := p4RtC.NewTableEntry(
				"k8s_dp_control.set_meta_tcp",
				map[string]client.MatchInterface{
					"hdr.ipv4.dst_addr": &client.ExactMatch{
						Value: Pack32BinaryIP4(podIpAddr[i]),
					},
					"hdr.tcp.dst_port": &client.ExactMatch{
						Value: valueToBytes16(portID[i]),
					},
				},
				p4RtC.NewTableActionDirect("k8s_dp_control.set_key_for_reverse_ct",
					[][]byte{valueToBytes(ModBlobPtrSnat)}),
				nil,
			)
			if err := p4RtC.InsertTableEntry(ctx, entryAdd); err != nil {
				log.Errorf("Cannot insert entry in 'set_meta_tcp table': %v", err)
				return err
			}
		}
	case Delete:
		for i := 0; i < len(podIpAddr); i++ {
			if net.ParseIP(podIpAddr[i]) == nil {
				err := fmt.Errorf("Invalid IP Address: %s", podIpAddr[i])
				return err
			}

			entryDelete := p4RtC.NewTableEntry(
				"k8s_dp_control.set_meta_tcp",
				map[string]client.MatchInterface{
					"hdr.ipv4.dst_addr": &client.ExactMatch{
						Value: Pack32BinaryIP4(podIpAddr[i]),
					},
					"hdr.tcp.dst_port": &client.ExactMatch{
						Value: valueToBytes16(portID[i]),
					},
				},
				nil,
				nil,
			)
			if err := p4RtC.DeleteTableEntry(ctx, entryDelete); err != nil {
				log.Errorf("Cannot delete entry from 'set_meta_tcp table': %v", err)
				return err
			}
		}
	default:
		log.Warnf("Invalid action %v", action)
		err := fmt.Errorf("Invalid action %v", action)
		return err
	}
	return nil
}

func SetMetaUdpTable(ctx context.Context, p4RtC *client.Client,
	podIpAddr []string, portID []uint16,
	ModBlobPtrSnat uint32, action InterfaceType) error {
	switch action {
	case Insert, Update:
		for i := 0; i < len(podIpAddr); i++ {
			if net.ParseIP(podIpAddr[i]) == nil {
				err := fmt.Errorf("Invalid IP Address: %s", podIpAddr[i])
				return err
			}

			entryAdd := p4RtC.NewTableEntry(
				"k8s_dp_control.set_meta_udp",
				map[string]client.MatchInterface{
					"hdr.ipv4.dst_addr": &client.ExactMatch{
						Value: Pack32BinaryIP4(podIpAddr[i]),
					},
					"hdr.udp.dst_port": &client.ExactMatch{
						Value: valueToBytes16(portID[i]),
					},
				},
				p4RtC.NewTableActionDirect("k8s_dp_control.set_key_for_reverse_ct",
					[][]byte{valueToBytes(ModBlobPtrSnat)}),
				nil,
			)
			if err := p4RtC.InsertTableEntry(ctx, entryAdd); err != nil {
				log.Errorf("Cannot insert entry in 'set_meta_udp table': %v", err)
				return err
			}
		}
	case Delete:
		for i := 0; i < len(podIpAddr); i++ {
			if net.ParseIP(podIpAddr[i]) == nil {
				err := fmt.Errorf("Invalid IP Address: %s", podIpAddr[i])
				return err
			}

			entryDelete := p4RtC.NewTableEntry(
				"k8s_dp_control.set_meta_udp",
				map[string]client.MatchInterface{
					"hdr.ipv4.dst_addr": &client.ExactMatch{
						Value: Pack32BinaryIP4(podIpAddr[i]),
					},
					"hdr.udp.dst_port": &client.ExactMatch{
						Value: valueToBytes16(portID[i]),
					},
				},
				nil,
				nil,
			)
			if err := p4RtC.DeleteTableEntry(ctx, entryDelete); err != nil {
				log.Errorf("Cannot delete entry from 'set_meta_udp table': %v", err)
				return err
			}
		}
	default:
		log.Warnf("Invalid action %v", action)
		err := fmt.Errorf("Invalid action %v", action)
		return err
	}
	return nil
}

func InsertServiceRules(ctx context.Context, p4RtC *client.Client,
	podIpAddr []string, portID []uint16, s store.Service,
	update bool) (err error, service store.Service) {
	var action InterfaceType
	var epNum uint32
	var groupID uint32

	if update {
		action = Update
	} else {
		action = Insert
	}

	memberID := make([]uint32, 0, len(podIpAddr))
	modblobPtrDNAT := make([]uint32, 0, len(podIpAddr))
	service = s

	if update {
		groupID = service.GroupID
		epNum = service.NumEndPoints
	} else {
		groupID = uuidFactory.getUUID()
		service.GroupID = groupID
		epNum = 0
	}

	for i := 0; i < len(podIpAddr); i, epNum = i+1, epNum+1 {
		id := uint32((groupID << 4) | ((epNum + 1) & 0xF))

		memberID = append(memberID, id)
		modblobPtrDNAT = append(modblobPtrDNAT, id)
		log.Infof("modblobPtrDNAT: %d memberid: %d, pod ip: %s, portID: %d",
			modblobPtrDNAT[i], memberID[i], podIpAddr[i], portID[i])

		serviceEp := store.ServiceEndPoint{
			IpAddress:      podIpAddr[i],
			Port:           uint32(portID[i]),
			MemberID:       id,
			ModBlobPtrDNAT: id,
		}
		service.ServiceEndPoint[podIpAddr[i]] = serviceEp
	}
	service.NumEndPoints = epNum

	log.Infof("group id: %d, service ip: %s, service mac: %s, service port: %d",
		groupID, service.ClusterIp, service.MacAddr, service.Port)

	if err = WriteDestIpTable(ctx, p4RtC, podIpAddr, portID,
		modblobPtrDNAT, action); err != nil {
		log.Errorf("Failed to WriteDestIpTable")
		return err, store.Service{}
	}
	log.Debugf("Inserted into table WriteDestIpTable, pod ip addrs: %v, port id: %v, mod blob ptrs: %v",
		podIpAddr, portID, modblobPtrDNAT)

	switch service.Proto {
	case "TCP":
		if err = AsSl3TcpTable(ctx, p4RtC, memberID, modblobPtrDNAT,
			groupID, action); err != nil {
			log.Errorf("Failed to AsSl3TcpTable")
			return err, store.Service{}
		}
		log.Debugf("Inserted into table AsSl3TcpTable, member ids: %v, mod blob ptrs: %v, group id: %d",
			memberID, modblobPtrDNAT, groupID)

		if err = SetMetaTcpTable(ctx, p4RtC, podIpAddr, portID, groupID, action); err != nil {
			log.Errorf("Failed to SetMetaTcpTable")
			return err, store.Service{}
		}
		log.Debugf("Inserted into table SetMetaTcpTable, pod ip addrs: %v, port id: %d, group id: %d",
			podIpAddr, portID, groupID)

		if action != Update {
			if err = TxBalanceTcpTable(ctx, p4RtC, service.ClusterIp,
				uint16(service.Port), groupID, action); err != nil {
				log.Errorf("Failed to TxBalanceTcpTable")
				return err, store.Service{}
			}
			log.Debugf("Inserted into the table TxBalanceTcpTable, service ip: %s, service port: %d, group id: %d",
				service.ClusterIp, uint16(service.Port), groupID)
		}
	case "UDP":
		if err = AsSl3UdpTable(ctx, p4RtC, memberID, modblobPtrDNAT,
			groupID, action); err != nil {
			log.Errorf("Failed to AsSl3UdpTable")
			return err, store.Service{}
		}
		log.Debugf("Inserted into table AsSl3UdpTable, member ids: %v, mod blob ptrs: %v, group id: %d",
			memberID, modblobPtrDNAT, groupID)

		if err = SetMetaUdpTable(ctx, p4RtC, podIpAddr, portID, groupID, action); err != nil {
			log.Errorf("Failed to SetMetaUdpTable")
			return err, store.Service{}
		}
		log.Debugf("Inserted into table SetMetaUdpTable, pod ip addrs: %v, port id: %d, group id: %d",
			podIpAddr, portID, groupID)

		if action != Update {
			if err = TxBalanceUdpTable(ctx, p4RtC, service.ClusterIp,
				uint16(service.Port), groupID, action); err != nil {
				log.Errorf("Failed to TxBalanceUdpTable")
				return err, store.Service{}
			}
			log.Debugf("Inserted into the table TxBalanceUdpTable, service ip: %s, service port: %d, group id: %d",
				service.ClusterIp, uint16(service.Port), groupID)
		}
	default:
		log.Errorf("Invalid protocol type")
		return fmt.Errorf("Invalid protocol type"), store.Service{}
	}

	if action != Update {
		if err = WriteSourceIpTable(ctx, p4RtC, groupID, service.ClusterIp,
			uint16(service.Port), action); err != nil {
			log.Errorf("Failed to WriteSourceIpTable")
			return err, store.Service{}
		}
		log.Debugf("Inserted into table WriteSourceIpTable, group id: %d, service ip: %s, service port: %d",
			groupID, service.ClusterIp, uint16(service.Port))
	}

	return nil, service
}

func DeleteServiceRules(ctx context.Context, p4RtC *client.Client,
	s store.Service) error {
	var err error
	var groupID uint32
	var service store.Service
	var podPortIDs []uint16
	var podIpAddrs []string
	var memberID []uint32
	var modblobPtrDNAT []uint32

	res := s.GetFromStore()
	if res == nil {
		err = fmt.Errorf("No GroupID found")
		return err
	}

	service = res.(store.Service)
	groupID = service.GroupID

	for _, ep := range service.ServiceEndPoint {
		podIpAddrs = append(podIpAddrs, ep.IpAddress)
		podPortIDs = append(podPortIDs, uint16(ep.Port))
		memberID = append(memberID, ep.MemberID)
		modblobPtrDNAT = append(modblobPtrDNAT, ep.ModBlobPtrDNAT)
		log.Infof("modblobPtrDNAT: %d memberid: %d, pod ip: %s, portID: %d",
			ep.ModBlobPtrDNAT, ep.MemberID, ep.IpAddress, ep.Port)
	}

	switch service.Proto {
	case "TCP":
		log.Debugf("Deleting from table TxBalanceTcpTable, service ip: %s, service port: %d, group id: %d",
			service.ClusterIp, uint16(service.Port), groupID)
		if err = TxBalanceTcpTable(ctx, p4RtC, service.ClusterIp, uint16(service.Port), groupID, Delete); err != nil {
			return err
		}
		log.Debugf("Deleting from table AsSl3TcpTable, member ids: %v, mod blob ptrs: %v, group id: %d",
			memberID, modblobPtrDNAT, groupID)
		if err = AsSl3TcpTable(ctx, p4RtC, memberID, modblobPtrDNAT, groupID, Delete); err != nil {
			return err
		}
		log.Debugf("Deleting from table SetMetaTcpTable, pod ip addrs: %v, port id: %d, group id: %d",
			podIpAddrs, podPortIDs, groupID)
		if err = SetMetaTcpTable(ctx, p4RtC, podIpAddrs, podPortIDs, groupID, Delete); err != nil {
			return err
		}

	case "UDP":
		log.Debugf("Deleting from table TxBalanceUdpTable, service ip: %s, service port: %d, group id: %d",
			service.ClusterIp, uint16(service.Port), groupID)

		if err = TxBalanceUdpTable(ctx, p4RtC, service.ClusterIp, uint16(service.Port), groupID, Delete); err != nil {
			return err
		}
		log.Debugf("Deleting from AsSl3UdpTable, member ids: %v, mod blob ptrs: %v, group id: %d",
			memberID, modblobPtrDNAT, groupID)
		if err = AsSl3UdpTable(ctx, p4RtC, memberID, modblobPtrDNAT, groupID, Delete); err != nil {
			return err
		}
		log.Debugf("Deleting from table SetMetaUdpTable, pod ip addrs: %v, port id: %d, group id: %d",
			podIpAddrs, podPortIDs, groupID)
		if err = SetMetaUdpTable(ctx, p4RtC, podIpAddrs, podPortIDs, groupID, Delete); err != nil {
			return err
		}
	default:
		log.Errorf("Invalid protocol type")
		return fmt.Errorf("Invalid protocol type")
	}

	log.Debugf("Deleting from table WriteDestIpTable, mod blob ptrs: %v", modblobPtrDNAT)
	err = WriteDestIpTable(ctx, p4RtC, nil, nil, modblobPtrDNAT, Delete)
	if err != nil {
		return err
	}

	log.Debugf("Deleting from table WriteSourceIpTable, group id: %d", groupID)
	err = WriteSourceIpTable(ctx, p4RtC, groupID, "", 0, Delete)
	if err != nil {
		return err
	}

	return nil
}
