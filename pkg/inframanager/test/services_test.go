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

package test

import (
	"context"
	"flag"
	"fmt"
	p4_v1 "github.com/p4lang/p4runtime/go/p4/v1"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"net"
	"path/filepath"
	"time"

	"github.com/antoninbas/p4runtime-go-client/pkg/client"
	"github.com/antoninbas/p4runtime-go-client/pkg/signals"
)

type InterfaceType int

const (
	HOST InterfaceType = iota
	PROXY
	ENDPOINT
	EXCEPTION
)

const (
	MAXUINT32              = 4294967295
	DEFAULT_UUID_CNT_CACHE = 512
)

var (
	podIps = [4]string{"10.10.10.1", "10.10.10.2", "10.10.10.3", "10.10.10.4"}
)

var (
	podMacs = [4]string{"00:1b:00:09:c5:80", "00:1b:00:0a:c5:80", "00:1b:00:0b:c5:80", "00:1b:00:0c:c5:80"}
)

var (
	serverIp = []string{"10.10.10.3"}
)

var (
	podPort = [4]uint32{0, 1, 2, 3}
)

var (
	serverMac = []string{"00:1b:00:0b:c5:80"}
)

var (
	servicePort uint32 = 20000
)

var (
	appPort = []uint32{10000, 10000}
)

var (
	serviceMacAddr = "00:00:00:aa:aa:aa"
)

var (
	serviceIpAddr = "10.10.100.1"
)

func MacToPortTable(ctx context.Context, p4RtC *client.Client, macAddr string, port uint32, flag bool) error {
	var err error

	mac, err := net.ParseMAC(macAddr)
	if err != nil {
		log.Errorf("Invalid Mac Address %s", macAddr)
		return err
	}

	if flag == true {
		entryAdd := p4RtC.NewTableEntry(
			"k8s_dp_control.mac_to_port_table",
			map[string]client.MatchInterface{
				"hdr.ethernet.dst_mac": &client.ExactMatch{
					Value: mac,
				},
			},
			p4RtC.NewTableActionDirect("k8s_dp_control.set_dest_vport", [][]byte{valueToBytes(port)}),
			nil,
		)

		if err = p4RtC.InsertTableEntry(ctx, entryAdd); err != nil {
			log.Errorf("Cannot insert entry into 'mac_to_port_table': %v", err)
			return err
		}

	} else {
		entryDelete := p4RtC.NewTableEntry(
			"k8s_dp_control.mac_to_port_table",
			map[string]client.MatchInterface{
				"hdr.ethernet.dst_mac": &client.ExactMatch{
					Value: mac,
				},
			},
			nil,
			nil,
		)

		if err = p4RtC.DeleteTableEntry(ctx, entryDelete); err != nil {
			log.Errorf("Cannot delete entry from 'mac_to_port_table': %v", err)
			return err
		}
	}

	return nil
}

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

func InsertCniRules(ctx context.Context, p4RtC *client.Client, macAddr string, ipAddr string, portId uint32) error {
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

	err = MacToPortTable(ctx, p4RtC, macAddr, uint32(portId), true)
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

	err = MacToPortTable(ctx, p4RtC, macAddr, 0, false)
	if err != nil {
		return err
	}
	return nil
}

func WriteDestIpTable(ctx context.Context, p4RtC *client.Client, podIpAddr []string, podMacAddr []string, portID []uint32, modBlobPtrDnat []uint32, addEntry bool) error {
	if addEntry {
		for i := 0; i < len(modBlobPtrDnat); i++ {
			dstMac, err := net.ParseMAC(podMacAddr[i])
			if err != nil {
				log.Errorf("Invalid mac address: %s, error: %v", podMacAddr[i], err)
				return err
			}

			if net.ParseIP(podIpAddr[i]) == nil {
				err = fmt.Errorf("Invalid IP address: %s", podIpAddr[i])
				return err
			}

			entryAdd := p4RtC.NewTableEntry(
				"k8s_dp_control.write_dest_ip_table",
				map[string]client.MatchInterface{
					"meta.mod_blob_ptr_dnat": &client.ExactMatch{
						Value: valueToBytes(modBlobPtrDnat[i]),
					},
				},
				p4RtC.NewTableActionDirect("k8s_dp_control.update_dst_ip_mac", [][]byte{dstMac,
					Pack32BinaryIP4(podIpAddr[i]),
					valueToBytes(portID[i])}),
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

func AsSl3TcpTable(ctx context.Context, p4RtC *client.Client, memberID []uint32, modBlobPtr []uint32, groupID uint32, addEntry bool) error {
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
			fmt.Println("AsSl3TcpTable inserted")
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
		int32(124),
	)
	if addEntry {
		if err = p4RtC.InsertActionProfileGroup(ctx, entryGroupTcp); err != nil {
			log.Errorf("Cannot insert group entry into 'as_sl3_tcp table': %v", err)
			return err
		}
		fmt.Println("AsSl3TcpTable group inserted")
	} else {
		if err = p4RtC.DeleteActionProfileGroup(ctx, entryGroupTcp); err != nil {
			log.Errorf("Cannot delete group entry from 'as_sl3_tcp table': %v", err)
			return err
		}
	}

	return nil
}

func TxBalanceTcpTable(ctx context.Context, p4RtC *client.Client, serviceIpAddr string, servicePort uint32, groupID uint32, addEntry bool) error {
	if net.ParseIP(serviceIpAddr) == nil {
		err := fmt.Errorf("Invalid IP Address: %s", serviceIpAddr)
		return err
	}

	mfs := map[string]client.MatchInterface{
		"hdr.ipv4.dst_addr": &client.ExactMatch{
			Value: Pack32BinaryIP4(serviceIpAddr),
		},
		"hdr.tcp.dst_port": &client.ExactMatch{
			Value: valueToBytes(servicePort),
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
		fmt.Println("TxBalanceTcpTable inserted")
	} else {
		if err := p4RtC.DeleteTableEntry(ctx, entryTcp); err != nil {
			log.Errorf("Cannot delete entry from 'tx_balance_tcp table': %v", err)
			return err
		}
	}
	return nil
}

func AsSl3UdpTable(ctx context.Context, p4RtC *client.Client, memberID []uint32, modBlobPtr []uint32, groupID uint32, addEntry bool) error {
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
			fmt.Println("AsSl3UdpTable member inserted")
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
		int32(124),
	)
	if addEntry {
		if err = p4RtC.InsertActionProfileGroup(ctx, entryGroupUdp); err != nil {
			log.Errorf("Cannot insert group entry into 'as_sl3_udp table': %v", err)
			return err
		}
		fmt.Println("AsSl3UdpTable group inserted")
	} else {
		if err = p4RtC.DeleteActionProfileGroup(ctx, entryGroupUdp); err != nil {
			log.Errorf("Cannot delete group entry from 'as_sl3_udp table': %v", err)
			return err
		}
	}

	return nil
}

func TxBalanceUdpTable(ctx context.Context, p4RtC *client.Client, serviceIpAddr string, servicePort uint32, groupID uint32, addEntry bool) error {
	if net.ParseIP(serviceIpAddr) == nil {
		err := fmt.Errorf("Invalid IP Address: %s", serviceIpAddr)
		return err
	}

	mfs := map[string]client.MatchInterface{
		"hdr.ipv4.dst_addr": &client.ExactMatch{
			Value: Pack32BinaryIP4(serviceIpAddr),
		},
		"hdr.udp.dst_port": &client.ExactMatch{
			Value: valueToBytes(servicePort),
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
		fmt.Println("TxBalanceUdpTable inserted")
	} else {
		if err := p4RtC.DeleteTableEntry(ctx, entryUdp); err != nil {
			log.Errorf("Cannot delete entry from 'tx_balance_udp table': %v", err)
			return err
		}
	}
	return nil
}

func WriteSourceIpTable(ctx context.Context, p4RtC *client.Client, ModBlobPtrSnat uint32, serviceIpAddr string, serviceMacAddr string, servicePort uint32, addEntry bool) error {
	if addEntry {
		srcMac, err := net.ParseMAC(serviceMacAddr)
		if err != nil {
			log.Errorf("Failed to parse mac address: %s, error: %v", serviceMacAddr, err)
			return err
		}

		if net.ParseIP(serviceIpAddr) == nil {
			err = fmt.Errorf("Invalid IP Address: %s", serviceIpAddr)
			return err
		}

		entryAdd := p4RtC.NewTableEntry(
			"k8s_dp_control.write_source_ip_table",
			map[string]client.MatchInterface{
				"meta.mod_blob_ptr_snat": &client.ExactMatch{
					Value: valueToBytes(ModBlobPtrSnat),
				},
			},
			p4RtC.NewTableActionDirect("k8s_dp_control.update_src_ip_mac", [][]byte{srcMac,
				Pack32BinaryIP4(serviceIpAddr),
				valueToBytes(servicePort)}),
			nil,
		)
		if err = p4RtC.InsertTableEntry(ctx, entryAdd); err != nil {
			log.Errorf("Cannot insert entry into 'write_source_ip_table table': %v", err)
			return err
		}
		fmt.Println("WriteSourceIpTable table")
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

func SetMetaTcpTable(ctx context.Context, p4RtC *client.Client, podIpAddr []string, portID []uint32, ModBlobPtrSnat uint32, addEntry bool) error {
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
						Value: valueToBytes(portID[i]),
					},
				},
				p4RtC.NewTableActionDirect("k8s_dp_control.set_key_for_reverse_ct", [][]byte{valueToBytes(ModBlobPtrSnat)}),
				nil,
			)
			if err := p4RtC.InsertTableEntry(ctx, entryAdd); err != nil {
				log.Errorf("Cannot insert entry in 'set_meta_tcp table': %v", err)
				return err
			}
			fmt.Println("SetMetaTcpTable inserted")
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
						Value: valueToBytes(portID[i]),
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

func SetMetaUdpTable(ctx context.Context, p4RtC *client.Client, podIpAddr []string, portID []uint32, ModBlobPtrSnat uint32, addEntry bool) error {
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
						Value: valueToBytes(portID[i]),
					},
				},
				p4RtC.NewTableActionDirect("k8s_dp_control.set_key_for_reverse_ct", [][]byte{valueToBytes(ModBlobPtrSnat)}),
				nil,
			)
			if err := p4RtC.InsertTableEntry(ctx, entryAdd); err != nil {
				log.Errorf("Cannot insert entry in 'set_meta_udp table': %v", err)
				return err
			}
			fmt.Println("SetMetaUdpTable inserted")
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
						Value: valueToBytes(portID[i]),
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

func InsertServiceRules(ctx context.Context, p4RtC *client.Client, podIpAddr []string, podMacAddr []string, portID []uint32, serviceIpAddr string, serviceMacAddr string, servicePort uint32) error {
	var err error
	memberID := make([]uint32, 0, len(podIpAddr))
	modblobPtrDNAT := make([]uint32, 0, len(podIpAddr))

	groupID := uuidFactory.getUUID()
	fmt.Println("group id: ", groupID)

	for i := 0; i < len(podIpAddr); i++ {
		val := uint32((groupID << 16) | uint32(i+1))
		memberID = append(memberID, val)
		modblobPtrDNAT = append(modblobPtrDNAT, val)
		fmt.Println("modblobPtrDNAT:  ,memberid: , pod ip: , pod mac: , portID: ", modblobPtrDNAT[i], memberID[i], podIpAddr[i], podMacAddr[i], portID[i])
	}

	err = WriteDestIpTable(ctx, p4RtC, podIpAddr, podMacAddr, portID, modblobPtrDNAT, true)
	if err != nil {
		fmt.Println("WriteDestIpTable failed")
		return err
	}

	err = AsSl3TcpTable(ctx, p4RtC, memberID, modblobPtrDNAT, groupID, true)
	if err != nil {
		fmt.Println("AsSl3TcpTable failed")
		return err
	}

	err = TxBalanceTcpTable(ctx, p4RtC, serviceIpAddr, servicePort, groupID, true)
	if err != nil {
		fmt.Println("TxBalanceTcpTable failed")
		return err
	}

	err = AsSl3UdpTable(ctx, p4RtC, memberID, modblobPtrDNAT, groupID, true)
	if err != nil {
		fmt.Println("AsSl3UdpTable failed")
		return err
	}

	err = TxBalanceUdpTable(ctx, p4RtC, serviceIpAddr, servicePort, groupID, true)
	if err != nil {
		fmt.Println("TxBalanceUdpTable failed")
		return err
	}

	err = WriteSourceIpTable(ctx, p4RtC, groupID, serviceIpAddr, serviceMacAddr, servicePort, true)
	if err != nil {
		fmt.Println("WriteSourceIpTable failed")
		return err
	}

	err = SetMetaTcpTable(ctx, p4RtC, podIpAddr, portID, groupID, true)
	if err != nil {
		fmt.Println("SetMetaTcpTable failed")
		return err
	}

	err = SetMetaUdpTable(ctx, p4RtC, podIpAddr, portID, groupID, true)
	if err != nil {
		fmt.Println("SetMetaUdpTable failed")
		return err
	}

	return nil
}

func SerivicesTest() {
	ctx := context.Background()

	p4InfoPath, _ := filepath.Abs("k8s_dp/p4info.txt")
	p4BinPath, _ := filepath.Abs("k8s_dp/k8s_dp.pb.bin")

	var addr string
	flag.StringVar(&addr, "addr", defaultAddr, "P4Runtime server socket")
	var deviceID uint64
	flag.Uint64Var(&deviceID, "device-id", defaultDeviceID, "Device id")
	var binPath string
	flag.StringVar(&binPath, "bin", p4BinPath, "Path to P4 bin")
	var p4infoPath string
	flag.StringVar(&p4infoPath, "p4info", p4InfoPath, "Path to P4Info")

	flag.Parse()

	if binPath == "" || p4infoPath == "" {
		log.Fatalf("Missing .bin or P4Info")
	}

	log.Infof("Connecting to server at %s", addr)
	conn, err := grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("Cannot connect to server: %v", err)
	}
	defer conn.Close()

	c := p4_v1.NewP4RuntimeClient(conn)
	resp, err := c.Capabilities(ctx, &p4_v1.CapabilitiesRequest{})
	if err != nil {
		log.Fatalf("Error in Capabilities RPC: %v", err)
	}
	log.Infof("P4Runtime server version is %s", resp.P4RuntimeApiVersion)

	stopCh := signals.RegisterSignalHandlers()

	electionID := &p4_v1.Uint128{High: 0, Low: 1}

	p4RtC := client.NewClient(c, deviceID, electionID)
	arbitrationCh := make(chan bool)
	go p4RtC.Run(stopCh, arbitrationCh, nil)

	waitCh := make(chan struct{})

	go func() {
		sent := false
		for isPrimary := range arbitrationCh {
			if isPrimary {
				log.Infof("We are the primary client!")
				if !sent {
					waitCh <- struct{}{}
					sent = true
				}
			} else {
				log.Infof("We are not the primary client!")
			}
		}
	}()

	func() {
		timeout := 5 * time.Second
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		select {
		case <-ctx.Done():
			log.Fatalf("Could not become the primary client within %v", timeout)
		case <-waitCh:
		}
	}()

	log.Info("Setting forwarding pipe")
	if _, err := p4RtC.SetFwdPipe(ctx, binPath, p4infoPath, 0); err != nil {
		log.Fatalf("Error when setting forwarding pipe: %v", err)
	}

	log.Info("installing the entries to the table")

	for i := 0; i < 4; i++ {
		err = InsertCniRules(ctx, p4RtC, podMacs[i], podIps[i], podPort[i])
		if err != nil {
			log.Fatalf("cannot insert cni rules")
		}
	}

	err = InsertServiceRules(ctx, p4RtC, serverIp, serverMac, appPort, serviceIpAddr, serviceMacAddr, servicePort)
	if err != nil {
		log.Fatalf("cannot insert service rules")
	}

	log.Info("Do Ctrl-C to quit")
	<-stopCh
	log.Info("Stopping client")
}
