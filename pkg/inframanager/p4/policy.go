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
	//	p4_v1 "github.com/p4lang/p4runtime/go/p4/v1"
	log "github.com/sirupsen/logrus"
	//	"net"
)

type tabletype int

const (
	denyall tabletype = iota
	NormalEntry
	SpecialEntry
)

func AclSrcIPProtoTable(ctx context.Context, p4RtC *client.Client,
	protocol string, workerep string, polID uint16, rangeID uint16,
	action InterfaceType) error {
	switch action {
	case Insert:
		if protocol != "" {
			entryAdd := p4RtC.NewTableEntry(
				"k8s_dp_control.acl_srcip_proto_table",
				map[string]client.MatchInterface{
					"hdr.ipv4.src_addr": &client.ExactMatch{
						Value: Pack32BinaryIP4(workerep),
					},
					"hdr.ipv4.protocol": &client.LpmMatch{
						Value: valueToBytesStr(protocol),
						PLen:  16,
					},
				},
				p4RtC.NewTableActionDirect("k8s_dp_control.set_range_check_ref",
					[][]byte{valueToBytes16(polID),
						valueToBytes16(rangeID)}),
				nil,
			)
			if err := p4RtC.InsertTableEntry(ctx, entryAdd); err != nil {
				log.Errorf("Cannot insert entry into 'acl_srcip_proto_table': %v", err)
				return err
			}
		} else {
			entryAdd := p4RtC.NewTableEntry(
				"k8s_dp_control.acl_srcip_proto_table",
				map[string]client.MatchInterface{
					"hdr.ipv4.src_addr": &client.ExactMatch{
						Value: Pack32BinaryIP4(workerep),
					},
					"hdr.ipv4.protocol": &client.LpmMatch{
						Value: valueToBytesStr(protocol),
						PLen:  16,
					},
				},
				p4RtC.NewTableActionDirect("k8s_dp_control.set_status_lookup_ipset_only",
					[][]byte{valueToBytes16(polID)}),
				nil,
			)
			if err := p4RtC.InsertTableEntry(ctx, entryAdd); err != nil {
				log.Errorf("Cannot insert entry into 'acl_srcip_proto_table': %v", err)
				return err
			}
		}

	case Delete:
		entryDelete := p4RtC.NewTableEntry(
			"k8s_dp_control.acl_srcip_proto_table",
			map[string]client.MatchInterface{
				"hdr.ipv4.src_addr": &client.ExactMatch{
					Value: Pack32BinaryIP4(workerep),
				},
				"hdr.ipv4.protocol": &client.LpmMatch{
					Value: valueToBytesStr(protocol),
					PLen:  16,
				},
			},
			nil,
			nil,
		)
		if err := p4RtC.DeleteTableEntry(ctx, entryDelete); err != nil {
			log.Errorf("Cannot delete entry from 'acl_srcip_proto_table': %v", err)
			return err
		}

	default:
		log.Warnf("Invalid action %v", action)
		err := fmt.Errorf("Invalid action %v", action)
		return err
	}

	return nil
}

func AclDstIPProtoTable(ctx context.Context, p4RtC *client.Client,
	protocol string, workerep string, polID uint16, rangeID uint16,
	action InterfaceType) error {
	switch action {
	case Insert:
		if protocol != "" {
			entryAdd := p4RtC.NewTableEntry(
				"k8s_dp_control.acl_dstip_proto_table",
				map[string]client.MatchInterface{
					"hdr.ipv4.dst_addr": &client.ExactMatch{
						Value: Pack32BinaryIP4(workerep),
					},
					"hdr.ipv4.protocol": &client.LpmMatch{
						Value: valueToBytesStr(protocol),
						PLen:  16,
					},
				},
				p4RtC.NewTableActionDirect("k8s_dp_control.set_range_check_ref",
					[][]byte{valueToBytes16(polID),
						valueToBytes16(rangeID)}),
				nil,
			)
			if err := p4RtC.InsertTableEntry(ctx, entryAdd); err != nil {
				log.Errorf("Cannot insert entry into 'acl_dstip_proto_table': %v", err)
				return err
			}
		} else {
			entryAdd := p4RtC.NewTableEntry(
				"k8s_dp_control.acl_dstip_proto_table",
				map[string]client.MatchInterface{
					"hdr.ipv4.dst_addr": &client.ExactMatch{
						Value: Pack32BinaryIP4(workerep),
					},
					"hdr.ipv4.protocol": &client.LpmMatch{
						Value: valueToBytesStr(protocol),
						PLen:  16,
					},
				},
				p4RtC.NewTableActionDirect("k8s_dp_control.set_status_lookup_ipset_only",
					[][]byte{valueToBytes16(polID)}),
				nil,
			)
			if err := p4RtC.InsertTableEntry(ctx, entryAdd); err != nil {
				log.Errorf("Cannot insert entry into 'acl_dstip_proto_table': %v", err)
				return err
			}
		}

	case Delete:
		entryDelete := p4RtC.NewTableEntry(
			"k8s_dp_control.acl_dstip_proto_table",
			map[string]client.MatchInterface{
				"hdr.ipv4.dst_addr": &client.ExactMatch{
					Value: Pack32BinaryIP4(workerep),
				},
				"hdr.ipv4.protocol": &client.LpmMatch{
					Value: valueToBytesStr(protocol),
					PLen:  16,
				},
			},
			nil,
			nil,
		)
		if err := p4RtC.DeleteTableEntry(ctx, entryDelete); err != nil {
			log.Errorf("Cannot delete entry from 'acl_dstip_proto_table': %v", err)
			return err
		}

	default:
		log.Warnf("Invalid action %v", action)
		err := fmt.Errorf("Invalid action %v", action)
		return err
	}

	return nil
}

func AclDstIpSetTable(ctx context.Context, p4RtC *client.Client,
	polID uint16, ipsetIP string, plen int32,
	mask uint32, action InterfaceType) error {
	switch action {
	case Insert:
		entryAdd := p4RtC.NewTableEntry(
			"k8s_dp_control.acl_dst_ipset_table",
			map[string]client.MatchInterface{
				"meta.acl_pol_id": &client.ExactMatch{
					Value: valueToBytes16(polID),
				},
				"hdr.ipv4.dst_addr": &client.LpmMatch{
					Value: Pack32BinaryIP4(ipsetIP),
					PLen:  plen,
				},
			},
			p4RtC.NewTableActionDirect("k8s_dp_control.acl_rip_allowed",
				[][]byte{valueToBytes(mask)}),
			nil,
		)
		if err := p4RtC.InsertTableEntry(ctx, entryAdd); err != nil {
			log.Errorf("Cannot insert entry into 'acl_dst_ipset_table': %v", err)
			return err
		}

	case Delete:
		entryDelete := p4RtC.NewTableEntry(
			"k8s_dp_control.acl_dst_ipset_table",
			map[string]client.MatchInterface{
				"meta.acl_pol_id": &client.ExactMatch{
					Value: valueToBytes16(polID),
				},
				"hdr.ipv4.dst_addr": &client.LpmMatch{
					Value: Pack32BinaryIP4(ipsetIP),
					PLen:  plen,
				},
			},
			nil,
			nil,
		)
		if err := p4RtC.DeleteTableEntry(ctx, entryDelete); err != nil {
			log.Errorf("Cannot delete entry from 'acl_dst_ipset_table': %v", err)
			return err
		}
	}

	return nil
}

func AclSrcIpSetTable(ctx context.Context, p4RtC *client.Client,
	polID uint16, ipsetIP string, plen int32,
	mask uint32, action InterfaceType) error {
	switch action {
	case Insert:
		entryAdd := p4RtC.NewTableEntry(
			"k8s_dp_control.acl_src_ipset_table",
			map[string]client.MatchInterface{
				"meta.acl_pol_id": &client.ExactMatch{
					Value: valueToBytes16(polID),
				},
				"hdr.ipv4.src_addr": &client.LpmMatch{
					Value: Pack32BinaryIP4(ipsetIP),
					PLen:  plen,
				},
			},
			p4RtC.NewTableActionDirect("k8s_dp_control.acl_rip_allowed",
				[][]byte{valueToBytes(mask)}),
			nil,
		)
		if err := p4RtC.InsertTableEntry(ctx, entryAdd); err != nil {
			log.Errorf("Cannot insert entry into 'acl_src_ipset_table': %v", err)
			return err
		}

	case Delete:
		entryDelete := p4RtC.NewTableEntry(
			"k8s_dp_control.acl_src_ipset_table",
			map[string]client.MatchInterface{
				"meta.acl_pol_id": &client.ExactMatch{
					Value: valueToBytes16(polID),
				},
				"hdr.ipv4.src_addr": &client.LpmMatch{
					Value: Pack32BinaryIP4(ipsetIP),
					PLen:  plen,
				},
			},
			nil,
			nil,
		)
		if err := p4RtC.DeleteTableEntry(ctx, entryDelete); err != nil {
			log.Errorf("Cannot delete entry from 'acl_src_ipset_table': %v", err)
			return err
		}
	}

	return nil
}

func TcpDstPortRcTable(ctx context.Context, p4RtC *client.Client,
	polID uint16, portrange []uint32,
	action InterfaceType) error {
	switch action {
	case Insert:
		entryAdd := p4RtC.NewTableEntry(
			"k8s_dp_control.tcp_dst_port_rc_table",
			map[string]client.MatchInterface{
				"meta.acl_pol_id": &client.ExactMatch{
					Value: valueToBytes16(polID),
				},
			},
			p4RtC.NewTableActionDirect("k8s_dp_control.do_range_check_tcp",
				[][]byte{valueToBytes(portrange[0]),
					valueToBytes(portrange[1]),
					valueToBytes(portrange[2]),
					valueToBytes(portrange[3]),
					valueToBytes(portrange[4]),
					valueToBytes(portrange[5]),
					valueToBytes(portrange[6]),
					valueToBytes(portrange[7]),
					valueToBytes(portrange[8]),
					valueToBytes(portrange[9]),
					valueToBytes(portrange[10]),
					valueToBytes(portrange[11]),
					valueToBytes(portrange[12]),
					valueToBytes(portrange[13]),
					valueToBytes(portrange[14]),
					valueToBytes(portrange[15])}),
			nil,
		)
		if err := p4RtC.InsertTableEntry(ctx, entryAdd); err != nil {
			log.Errorf("Cannot insert entry into 'tcp_dst_port_rc_table': %v", err)
			return err
		}

	case Delete:
		entryDelete := p4RtC.NewTableEntry(
			"k8s_dp_control.tcp_dst_port_rc_table",
			map[string]client.MatchInterface{
				"meta.acl_pol_id": &client.ExactMatch{
					Value: valueToBytes16(polID),
				},
			},
			nil,
			nil,
		)
		if err := p4RtC.DeleteTableEntry(ctx, entryDelete); err != nil {
			log.Errorf("Cannot delete entry from 'tcp_dst_port_rc_table': %v", err)
			return err
		}
	}

	return nil
}

func UdpDstPortRcTable(ctx context.Context, p4RtC *client.Client,
	polID uint16, portrange []uint32,
	action InterfaceType) error {
	switch action {
	case Insert:
		entryAdd := p4RtC.NewTableEntry(
			"k8s_dp_control.udp_dst_port_rc_table",
			map[string]client.MatchInterface{
				"meta.acl_pol_id": &client.ExactMatch{
					Value: valueToBytes16(polID),
				},
			},
			p4RtC.NewTableActionDirect("k8s_dp_control.do_range_check_udp",
				[][]byte{valueToBytes(portrange[0]),
					valueToBytes(portrange[1]),
					valueToBytes(portrange[2]),
					valueToBytes(portrange[3]),
					valueToBytes(portrange[4]),
					valueToBytes(portrange[5]),
					valueToBytes(portrange[6]),
					valueToBytes(portrange[7]),
					valueToBytes(portrange[8]),
					valueToBytes(portrange[9]),
					valueToBytes(portrange[10]),
					valueToBytes(portrange[11]),
					valueToBytes(portrange[12]),
					valueToBytes(portrange[13]),
					valueToBytes(portrange[14]),
					valueToBytes(portrange[15])}),
			nil,
		)
		if err := p4RtC.InsertTableEntry(ctx, entryAdd); err != nil {
			log.Errorf("Cannot insert entry into 'udp_dst_port_rc_table': %v", err)
			return err
		}

	case Delete:
		entryDelete := p4RtC.NewTableEntry(
			"k8s_dp_control.udp_dst_port_rc_table",
			map[string]client.MatchInterface{
				"meta.acl_pol_id": &client.ExactMatch{
					Value: valueToBytes16(polID),
				},
			},
			nil,
			nil,
		)
		if err := p4RtC.DeleteTableEntry(ctx, entryDelete); err != nil {
			log.Errorf("Cannot delete entry from 'udp_dst_port_rc_table': %v", err)
			return err
		}
	}

	return nil
}

func InsertPolicyTableEntries(tbltype tabletype, workerep string) bool {
	//	case NormalEntry:
	//
	// []policyname = store.workerepmap[workerep] //get the policy name from
	// worker ep
}
