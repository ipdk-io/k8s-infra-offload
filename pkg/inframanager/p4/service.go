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
	addEntry bool) error {
	if addEntry {
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
	} else {
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
	}
	return nil
}

func AsSl3TcpTable(ctx context.Context, p4RtC *client.Client,
	memberID []uint32, modBlobPtr []uint32,
	groupID uint32, addEntry bool) error {
	var err error
	var memberList []*p4_v1.ActionProfileGroup_Member

	for i := 0; i < len(memberID); i++ {
		member := &p4_v1.ActionProfileGroup_Member{
			MemberId: memberID[i],
		}
		memberList = append(memberList, member)

		entryMemberTcp := p4RtC.NewActionProfileMember(
			"k8s_dp_control.as_sl3_tcp",
			memberID[i],
			"k8s_dp_control.set_default_lb_dest",
			[][]byte{valueToBytes(modBlobPtr[i])},
		)
		if addEntry {
			if err = p4RtC.InsertActionProfileMember(ctx, entryMemberTcp); err != nil {
				log.Errorf("Cannot insert member entry into 'as_sl3_tcp table': %v", err)
				return err
			}
		} else {
			if err = p4RtC.DeleteActionProfileMember(ctx, entryMemberTcp); err != nil {
				log.Errorf("Cannot delete member entry from 'as_sl3_tcp table': %v", err)
				return err
			}
		}
	}

	entryGroupTcp := p4RtC.NewActionProfileGroup(
		"k8s_dp_control.as_sl3_tcp",
		groupID,
		memberList,
		int32(128),
	)
	if addEntry {
		if err = p4RtC.InsertActionProfileGroup(ctx, entryGroupTcp); err != nil {
			log.Errorf("Cannot insert group entry into 'as_sl3_tcp table': %v", err)
			return err
		}
	} else {
		if err = p4RtC.DeleteActionProfileGroup(ctx, entryGroupTcp); err != nil {
			log.Errorf("Cannot delete group entry from 'as_sl3_tcp table': %v", err)
			return err
		}
	}

	return nil
}

func AsSl3UdpTable(ctx context.Context, p4RtC *client.Client,
	memberID []uint32, modBlobPtr []uint32,
	groupID uint32, addEntry bool) error {
	var err error
	var memberList []*p4_v1.ActionProfileGroup_Member

	for i := 0; i < len(memberID); i++ {
		member := &p4_v1.ActionProfileGroup_Member{
			MemberId: memberID[i],
		}
		memberList = append(memberList, member)

		entryMemberUdp := p4RtC.NewActionProfileMember(
			"k8s_dp_control.as_sl3_udp",
			memberID[i],
			"k8s_dp_control.set_default_lb_dest",
			[][]byte{valueToBytes(modBlobPtr[i])},
		)
		if addEntry {
			if err = p4RtC.InsertActionProfileMember(ctx, entryMemberUdp); err != nil {
				log.Errorf("Cannot insert member entry into 'as_sl3_udp table': %v", err)
				return err
			}
		} else {
			if err = p4RtC.DeleteActionProfileMember(ctx, entryMemberUdp); err != nil {
				log.Errorf("Cannot delete member entry from 'as_sl3_udp table': %v", err)
				return err
			}
		}
	}

	entryGroupUdp := p4RtC.NewActionProfileGroup(
		"k8s_dp_control.as_sl3_udp",
		groupID,
		memberList,
		int32(128),
	)
	if addEntry {
		if err = p4RtC.InsertActionProfileGroup(ctx, entryGroupUdp); err != nil {
			log.Errorf("Cannot insert group entry into 'as_sl3_udp table': %v", err)
			return err
		}
	} else {
		if err = p4RtC.DeleteActionProfileGroup(ctx, entryGroupUdp); err != nil {
			log.Errorf("Cannot delete group entry from 'as_sl3_udp table': %v", err)
			return err
		}
	}

	return nil
}

func TxBalanceTcpTable(ctx context.Context, p4RtC *client.Client,
	serviceIpAddr string, servicePort uint16,
	groupID uint32, addEntry bool) error {
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
	if addEntry {
		if err := p4RtC.InsertTableEntry(ctx, entryTcp); err != nil {
			log.Errorf("Cannot insert entry into 'tx_balance_tcp table': %v", err)
			return err
		}
	} else {
		if err := p4RtC.DeleteTableEntry(ctx, entryTcp); err != nil {
			log.Errorf("Cannot delete entry from 'tx_balance_tcp table': %v", err)
			return err
		}
	}
	return nil
}

func TxBalanceUdpTable(ctx context.Context, p4RtC *client.Client,
	serviceIpAddr string, servicePort uint16,
	groupID uint32, addEntry bool) error {
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
	if addEntry {
		if err := p4RtC.InsertTableEntry(ctx, entryUdp); err != nil {
			log.Errorf("Cannot insert entry into 'tx_balance_udp table': %v", err)
			return err
		}
	} else {
		if err := p4RtC.DeleteTableEntry(ctx, entryUdp); err != nil {
			log.Errorf("Cannot delete entry from 'tx_balance_udp table': %v", err)
			return err
		}
	}
	return nil
}

func WriteSourceIpTable(ctx context.Context, p4RtC *client.Client,
	ModBlobPtrSnat uint32, serviceIpAddr string, servicePort uint16,
	addEntry bool) error {
	if addEntry {
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
	} else {
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
	}

	return nil
}

func SetMetaTcpTable(ctx context.Context, p4RtC *client.Client,
	podIpAddr []string, portID []uint16,
	ModBlobPtrSnat uint32, addEntry bool) error {
	if addEntry {
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
	} else {
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
	}
	return nil
}

func SetMetaUdpTable(ctx context.Context, p4RtC *client.Client,
	podIpAddr []string, portID []uint16,
	ModBlobPtrSnat uint32, addEntry bool) error {
	if addEntry {
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
	} else {
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
	}
	return nil
}

func InsertServiceRules(ctx context.Context, p4RtC *client.Client,
	podIpAddr []string, podMacAddr []string,
	portID []uint16, serviceIpAddr string,
	serviceMacAddr string,
	servicePort uint16) (err error, groupID uint32) {

	memberID := make([]uint32, 0, len(podIpAddr))
	modblobPtrDNAT := make([]uint32, 0, len(podIpAddr))

	groupID = uuidFactory.getUUID()

	for i := 0; i < len(podIpAddr); i++ {
		val := uint32((groupID << 16) | uint32(i+1))
		memberID = append(memberID, val)
		modblobPtrDNAT = append(modblobPtrDNAT, val)
		log.Infof("modblobPtrDNAT: %d memberid: %d, pod ip: %s, pod mac: %s, portID: %d", modblobPtrDNAT[i], memberID[i], podIpAddr[i], podMacAddr[i], portID[i])
	}

	log.Infof("group id: %d, service ip: %s,service mac: %s, service port: %d", groupID, serviceIpAddr, serviceMacAddr, servicePort)

	if err = WriteDestIpTable(ctx, p4RtC, podIpAddr, portID,
		modblobPtrDNAT, true); err != nil {
		log.Errorf("Failed to WriteDestIpTable")
		return
	}

	if err = AsSl3TcpTable(ctx, p4RtC, memberID, modblobPtrDNAT,
		groupID, true); err != nil {
		log.Errorf("Failed to AsSl3TcpTable")
		return
	}

	if err = TxBalanceTcpTable(ctx, p4RtC, serviceIpAddr, servicePort,
		groupID, true); err != nil {
		log.Errorf("Failed to TxBalanceTcpTable")
		return
	}

	if err = AsSl3UdpTable(ctx, p4RtC, memberID, modblobPtrDNAT,
		groupID, true); err != nil {
		log.Errorf("Failed to AsSl3UdpTable")
		return
	}

	if err = TxBalanceUdpTable(ctx, p4RtC, serviceIpAddr,
		servicePort, groupID, true); err != nil {
		log.Errorf("Failed to TxBalanceUdpTable")
		return
	}

	if err = WriteSourceIpTable(ctx, p4RtC, groupID,
		serviceIpAddr, servicePort, true); err != nil {
		log.Errorf("Failed to WriteSourceIpTable")
		return
	}

	if err = SetMetaTcpTable(ctx, p4RtC, podIpAddr, portID, groupID, true); err != nil {
		log.Errorf("Failed to SetMetaTcpTable")
		return
	}

	if err = SetMetaUdpTable(ctx, p4RtC, podIpAddr, portID, groupID, true); err != nil {
		log.Errorf("Failed to SetMetaUdpTable")
	}

	return
}

func DeleteServiceRules(ctx context.Context, p4RtC *client.Client, podIpAddr []string,
	podMacAddr []string, portID []uint16, serviceIpAddr string,
	serviceMacAddr string, servicePort uint16) error {
	var err error
	var groupID uint32

	memberID := make([]uint32, 0, len(podIpAddr))
	modblobPtrDNAT := make([]uint32, 0, len(podIpAddr))
	s := store.Service{
		ClusterIp: serviceIpAddr,
	}
	res := s.GetFromStore()
	if res != nil {
		serviceEntry := res.(store.Service)
		groupID = serviceEntry.GroupID
	} else {
		err = fmt.Errorf("No GroupID found")
		return err
	}

	for i := 0; i < len(podIpAddr); i++ {
		val := uint32((groupID << 16) | uint32(i+1))
		memberID = append(memberID, val)
		modblobPtrDNAT = append(modblobPtrDNAT, val)
		log.Infof("modblobPtrDNAT: %d memberid: %d, pod ip: %s, pod mac: %s,portID: %d", modblobPtrDNAT[i], memberID[i], podIpAddr[i], podMacAddr[i], portID[i])
	}

	err = WriteDestIpTable(ctx, p4RtC, nil, nil, modblobPtrDNAT, false)
	if err != nil {
		return err
	}

	err = AsSl3TcpTable(ctx, p4RtC, memberID, modblobPtrDNAT, groupID, false)
	if err != nil {
		return nil
	}

	err = AsSl3UdpTable(ctx, p4RtC, memberID, modblobPtrDNAT, groupID, false)
	if err != nil {
		return nil
	}

	err = TxBalanceTcpTable(ctx, p4RtC, serviceIpAddr, servicePort, groupID, false)
	if err != nil {
		return err
	}

	err = TxBalanceUdpTable(ctx, p4RtC, serviceIpAddr, servicePort, groupID, false)
	if err != nil {
		return nil
	}

	err = WriteSourceIpTable(ctx, p4RtC, groupID, "", 0, false)
	if err != nil {
		return nil
	}

	err = SetMetaTcpTable(ctx, p4RtC, podIpAddr, portID, 0, false)
	if err != nil {
		return nil
	}

	err = SetMetaUdpTable(ctx, p4RtC, podIpAddr, portID, 0, false)
	if err != nil {
		return nil
	}

	return nil
}
