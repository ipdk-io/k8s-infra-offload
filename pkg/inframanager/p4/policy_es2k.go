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
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/antoninbas/p4runtime-go-client/pkg/client"
	"github.com/ipdk-io/k8s-infra-offload/pkg/inframanager/store"
	"github.com/ipdk-io/k8s-infra-offload/pkg/utils"
	p4_v1 "github.com/p4lang/p4runtime/go/p4/v1"
	log "github.com/sirupsen/logrus"
	//	"net"
)

type OperationType int

const (
	DenyAll OperationType = iota
	PolicyAdd
	PolicyDel
	PolicyUpdate
	WorkloadAdd
	WorkloadUpdate
	WorkloadDel
	IpsetAdd
	IpsetUpdate
	IpsetDel
)

func CheckAclResult(ctx context.Context, p4RtC *client.Client,
	acl_status uint8, range_check_result uint8, range_check_mask uint8,
	ipset_check_result uint8, ipset_check_mask uint8,
	priority uint16, aclAction string, action InterfaceType) error {
	var entry *p4_v1.TableEntry
	var actionName string
	var tableName string

	if aclAction == "allow" {
		actionName = "k8s_dp_control.allow"
	} else {
		actionName = "k8s_dp_control.deny"
	}

	switch action {
	case Insert:
		tableName = "k8s_dp_control.check_acl_result"
		entry = p4RtC.NewTableEntry(
			tableName,
			map[string]client.MatchInterface{
				"user_meta.gmeta.acl_status": &client.ExactMatch{
					Value: ToBytes(acl_status),
				},
				"meta.fxp_internal.range_check_result": &client.TernaryMatch{
					Value: ToBytes(range_check_result),
					Mask:  ToBytes(range_check_mask),
				},
				"user_meta.gmeta.ipset_check_result": &client.TernaryMatch{
					Value: ToBytes(ipset_check_result),
					Mask:  ToBytes(ipset_check_mask),
				},
			},
			//p4RtC.NewTableActionDirect(actionName, [][]byte{ToBytes(aclAction)}),
			p4RtC.NewTableActionDirect(actionName, nil),
			//nil,
			&client.TableEntryOptions{
				IdleTimeout: 0,
				Priority:    int32(priority),
			},
		)
		if err := p4RtC.InsertTableEntry(ctx, entry); err != nil {
			log.Errorf("Cannot insert entry into %s: %v", tableName, err)
			return err
		}

	case Delete:
		tableName = "k8s_dp_control.check_acl_result"
		entry = p4RtC.NewTableEntry(
			tableName,
			map[string]client.MatchInterface{
				"user_meta.gmeta.acl_status": &client.ExactMatch{
					Value: ToBytes(acl_status),
				},
				"meta.fxp_internal.range_check_result": &client.TernaryMatch{
					Value: ToBytes(range_check_result),
					Mask:  ToBytes(range_check_mask),
				},
				"user_meta.gmeta.ipset_check_result": &client.TernaryMatch{
					Value: ToBytes(ipset_check_result),
					Mask:  ToBytes(ipset_check_mask),
				},
			},
			nil,
			&client.TableEntryOptions{
				IdleTimeout: 0,
				Priority:    int32(priority),
			},
		)
		if err := p4RtC.DeleteTableEntry(ctx, entry); err != nil {
			log.Errorf("Cannot delete entry from %s: %v", tableName, err)
			return err
		}
	default:
		log.Warnf("Invalid action %v", action)
		err := fmt.Errorf("Invalid action %v", action)
		return err
	}
	return nil
}

func AclPodIpProtoTable(ctx context.Context, p4RtC *client.Client,
	protocol uint8, workerep string, ipsetID uint16, rangeID uint16, direction string,
	action InterfaceType) error {
	var tableName string
	var entryAdd *p4_v1.TableEntry
	var entryDelete *p4_v1.TableEntry
	switch action {
	case Insert:
		if direction == "TX" {
			if protocol == PROTO_TCP {
				// protocol = 6 (TCP)
				tableName = "k8s_dp_control.acl_pod_ip_proto_table_egress"
				entryAdd = p4RtC.NewTableEntry(
					"k8s_dp_control.acl_pod_ip_proto_table_egress",
					map[string]client.MatchInterface{
						"hdrs.ipv4[meta.common.depth].src_ip": &client.ExactMatch{
							Value: Pack32BinaryIP4(workerep),
						},
						"hdrs.ipv4[meta.common.depth].protocol": &client.ExactMatch{
							Value: ToBytes(protocol),
						},
					},
					p4RtC.NewTableActionDirect("k8s_dp_control.set_range_check_ref_tcp_egress",
						[][]byte{ToBytes(rangeID),
							ToBytes(ipsetID)}),
					nil,
				)
			} else if protocol == PROTO_UDP {
				// protocol = 17 (UDP)
				tableName = "k8s_dp_control.acl_pod_ip_proto_table_egress"
				entryAdd = p4RtC.NewTableEntry(
					"k8s_dp_control.acl_pod_ip_proto_table_egress",
					map[string]client.MatchInterface{
						"hdrs.ipv4[meta.common.depth].src_ip": &client.ExactMatch{
							Value: Pack32BinaryIP4(workerep),
						},
						"hdrs.ipv4[meta.common.depth].protocol": &client.ExactMatch{
							Value: ToBytes(protocol),
						},
					},
					p4RtC.NewTableActionDirect("k8s_dp_control.set_range_check_ref_udp_egress",
						[][]byte{ToBytes(rangeID),
							ToBytes(ipsetID)}),
					nil,
				)
			} else {
				// protocol = 0, i.e. no protocol is specified
				tableName = "k8s_dp_control.acl_pod_ip_table_egress"
				entryAdd = p4RtC.NewTableEntry(
					"k8s_dp_control.acl_pod_ip_table_egress",
					map[string]client.MatchInterface{
						"hdrs.ipv4[meta.common.depth].src_ip": &client.ExactMatch{
							Value: Pack32BinaryIP4(workerep),
						},
					},
					// TODO: Since only one action is allowed right now, adding only set_status_match_ipset_only_egress.
					// After enabling multiple actions per table, we need to account fir allow_all and deny_all cases.
					p4RtC.NewTableActionDirect("k8s_dp_control.set_status_match_ipset_only_egress",
						[][]byte{ToBytes(ipsetID)}),
					nil,
				)
			}
			if err := p4RtC.InsertTableEntry(ctx, entryAdd); err != nil {
				log.Errorf("Cannot insert entry into %s: %v", tableName, err)
				return err
			}
		} else {
			// direction = RX
			tableName = "k8s_dp_control.acl_pod_ip_proto_table_ingress"
			if protocol == PROTO_TCP {
				entryAdd = p4RtC.NewTableEntry(
					"k8s_dp_control.acl_pod_ip_proto_table_ingress",
					map[string]client.MatchInterface{
						"hdrs.ipv4[meta.common.depth].dst_ip": &client.ExactMatch{
							Value: Pack32BinaryIP4(workerep),
						},
						"hdrs.ipv4[meta.common.depth].protocol": &client.ExactMatch{
							Value: ToBytes(protocol),
						},
					},
					p4RtC.NewTableActionDirect("k8s_dp_control.set_range_check_ref_tcp_ingress",
						[][]byte{ToBytes(rangeID),
							ToBytes(ipsetID)}),
					nil,
				)
			} else if protocol == PROTO_UDP {
				entryAdd = p4RtC.NewTableEntry(
					"k8s_dp_control.acl_pod_ip_proto_table_ingress",
					map[string]client.MatchInterface{
						"hdrs.ipv4[meta.common.depth].dst_ip": &client.ExactMatch{
							Value: Pack32BinaryIP4(workerep),
						},
						"hdrs.ipv4[meta.common.depth].protocol": &client.ExactMatch{
							Value: ToBytes(protocol),
						},
					},
					p4RtC.NewTableActionDirect("k8s_dp_control.set_range_check_ref_udp_ingress",
						[][]byte{ToBytes(rangeID),
							ToBytes(ipsetID)}),
					nil,
				)
			} else {
				// protocol = 0, i.e. no protocol is specified
				tableName = "k8s_dp_control.acl_pod_ip_table_ingress"
				entryAdd = p4RtC.NewTableEntry(
					"k8s_dp_control.acl_pod_ip_table_ingress",
					map[string]client.MatchInterface{
						"hdrs.ipv4[meta.common.depth].dst_ip": &client.ExactMatch{
							Value: Pack32BinaryIP4(workerep),
						},
					},
					p4RtC.NewTableActionDirect("k8s_dp_control.set_status_match_ipset_only_ingress",
						[][]byte{ToBytes(ipsetID)}),
					nil,
				)
			}
			if err := p4RtC.InsertTableEntry(ctx, entryAdd); err != nil {
				log.Errorf("Cannot insert entry into %s: %v", tableName, err)
				return err
			}
		}

	case Delete:
		if direction == "TX" {
			if protocol != 0 {
				tableName = "k8s_dp_control.acl_pod_ip_proto_table_egress"
				entryDelete = p4RtC.NewTableEntry(
					"k8s_dp_control.acl_pod_ip_proto_table_egress",
					map[string]client.MatchInterface{
						"hdrs.ipv4[meta.common.depth].src_ip": &client.ExactMatch{
							Value: Pack32BinaryIP4(workerep),
						},
						"hdrs.ipv4[meta.common.depth].protocol": &client.ExactMatch{
							Value: ToBytes(protocol),
						},
					},
					nil,
					nil,
				)
			} else {
				tableName = "k8s_dp_control.acl_pod_ip_table_egress"
				entryDelete = p4RtC.NewTableEntry(
					"k8s_dp_control.acl_pod_ip_table_egress",
					map[string]client.MatchInterface{
						"hdrs.ipv4[meta.common.depth].src_ip": &client.ExactMatch{
							Value: Pack32BinaryIP4(workerep),
						},
					},
					nil,
					nil,
				)
			}

			if err := p4RtC.DeleteTableEntry(ctx, entryDelete); err != nil {
				log.Errorf("Cannot delete entry from %s: %v", tableName, err)
				return err
			}
		} else {
			if protocol != 0 {
				tableName = "k8s_dp_control.acl_pod_ip_proto_table_ingress"
				entryDelete = p4RtC.NewTableEntry(
					"k8s_dp_control.acl_pod_ip_proto_table_ingress",
					map[string]client.MatchInterface{
						"hdrs.ipv4[meta.common.depth].dst_ip": &client.ExactMatch{
							Value: Pack32BinaryIP4(workerep),
						},
						"hdrs.ipv4[meta.common.depth].protocol": &client.ExactMatch{
							Value: ToBytes(protocol),
						},
					},
					nil,
					nil,
				)
			} else {
				tableName = "k8s_dp_control.acl_pod_ip_table_ingress"
				entryDelete = p4RtC.NewTableEntry(
					"k8s_dp_control.acl_pod_ip_table_ingress",
					map[string]client.MatchInterface{
						"hdrs.ipv4[meta.common.depth].dst_ip": &client.ExactMatch{
							Value: Pack32BinaryIP4(workerep),
						},
					},
					nil,
					nil,
				)
			}

			if err := p4RtC.DeleteTableEntry(ctx, entryDelete); err != nil {
				log.Errorf("Cannot delete entry from %s: %v", tableName, err)
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

func AclPodIpTableDenyAll(ctx context.Context, p4RtC *client.Client,
	protocol uint8, workerep string, direction string,
	action InterfaceType) error {
	var tableName string
	var entryAdd *p4_v1.TableEntry
	var entryDelete *p4_v1.TableEntry
	switch action {
	case Insert:
		if direction == "TX" {
			tableName = "k8s_dp_control.acl_pod_ip_table_egress"
			entryAdd = p4RtC.NewTableEntry(
				"k8s_dp_control.acl_pod_ip_table_egress",
				map[string]client.MatchInterface{
					"hdrs.ipv4[meta.common.depth].src_ip": &client.ExactMatch{
						Value: Pack32BinaryIP4(workerep),
					},
				},
				p4RtC.NewTableActionDirect("k8s_dp_control.set_status_deny_all", nil),
				nil,
			)
		} else {
			// direction = RX
			tableName = "k8s_dp_control.acl_pod_ip_table_ingress"
			entryAdd = p4RtC.NewTableEntry(
				"k8s_dp_control.acl_pod_ip_table_ingress",
				map[string]client.MatchInterface{
					"hdrs.ipv4[meta.common.depth].dst_ip": &client.ExactMatch{
						Value: Pack32BinaryIP4(workerep),
					},
				},
				p4RtC.NewTableActionDirect("k8s_dp_control.set_status_deny_all", nil),
				nil,
			)
		}
		if err := p4RtC.InsertTableEntry(ctx, entryAdd); err != nil {
			log.Errorf("Cannot insert DenyAll entry into %s: %v", tableName, err)
			return err
		}
	case Delete:
		if direction == "TX" {
			tableName = "k8s_dp_control.acl_pod_ip_table_egress"
			entryDelete = p4RtC.NewTableEntry(
				"k8s_dp_control.acl_pod_ip_table_egress",
				map[string]client.MatchInterface{
					"hdrs.ipv4[meta.common.depth].src_ip": &client.ExactMatch{
						Value: Pack32BinaryIP4(workerep),
					},
				},
				nil,
				nil,
			)
		} else {
			tableName = "k8s_dp_control.acl_pod_ip_table_ingress"
			entryDelete = p4RtC.NewTableEntry(
				"k8s_dp_control.acl_pod_ip_table_ingress",
				map[string]client.MatchInterface{
					"hdrs.ipv4[meta.common.depth].dst_ip": &client.ExactMatch{
						Value: Pack32BinaryIP4(workerep),
					},
				},
				nil,
				nil,
			)
		}

		if err := p4RtC.DeleteTableEntry(ctx, entryDelete); err != nil {
			log.Errorf("Cannot delete DenyAll entry from %s: %v", tableName, err)
			return err
		}

	default:
		log.Warnf("Invalid action %v", action)
		err := fmt.Errorf("Invalid action %v", action)
		return err
	}
	return nil
}

func AclLpmRootLutTable(ctx context.Context, p4RtC *client.Client,
	ipsetID uint16, direction string, action InterfaceType) error {
	var tableName string
	var entryAdd *p4_v1.TableEntry
	var entryDelete *p4_v1.TableEntry

	//TODO: Find a better way to come up with priority
	priority := ipsetID

	switch action {
	case Insert:
		if direction == "TX" {
			tcam_key := uint32((ipsetID << 8) | (1 & 0xFF))

			tableName = "k8s_dp_control.acl_lpm_root_lut_egress"
			entryAdd = p4RtC.NewTableEntry(
				"k8s_dp_control.acl_lpm_root_lut_egress",
				map[string]client.MatchInterface{
					"user_meta.gmeta.tcam_key": &client.TernaryMatch{
						Value: ToBytes(tcam_key),
						Mask:  ToBytes(uint32(0xFFFFFFFF)),
					},
				},
				p4RtC.NewTableActionDirect("k8s_dp_control.acl_lpm_root_lut_egress_action",
					[][]byte{ToBytes(ipsetID)}),
				//nil,
				&client.TableEntryOptions{
					IdleTimeout: 0,
					Priority:    int32(priority),
				},
			)
		} else {
			tcam_key := uint32((ipsetID << 8) | (0 & 0xFF))
			tableName = "k8s_dp_control.acl_lpm_root_lut_ingress"
			entryAdd = p4RtC.NewTableEntry(
				"k8s_dp_control.acl_lpm_root_lut_ingress",
				map[string]client.MatchInterface{
					"user_meta.gmeta.tcam_key": &client.TernaryMatch{
						Value: ToBytes(tcam_key),
						Mask:  ToBytes(uint32(0xFFFFFFFF)),
					},
				},
				p4RtC.NewTableActionDirect("k8s_dp_control.acl_lpm_root_lut_ingress_action",
					[][]byte{ToBytes(ipsetID)}),
				&client.TableEntryOptions{
					IdleTimeout: 0,
					Priority:    int32(priority),
				},
			)
		}
		if err := p4RtC.InsertTableEntry(ctx, entryAdd); err != nil {
			log.Errorf("Cannot insert entry into %s: %v", tableName, err)
			return err
		}

	case Delete:
		if direction == "TX" {
			tcam_key := uint32((ipsetID << 8) | (1 & 0xFF))

			tableName = "k8s_dp_control.acl_lpm_root_lut_egress"
			entryDelete = p4RtC.NewTableEntry(
				"k8s_dp_control.acl_lpm_root_lut_egress",
				map[string]client.MatchInterface{
					"user_meta.gmeta.tcam_key": &client.TernaryMatch{
						Value: ToBytes(tcam_key),
						Mask:  ToBytes(uint32(0xFFFFFFFF)),
					},
				},
				nil,
				&client.TableEntryOptions{
					IdleTimeout: 0,
					Priority:    int32(priority),
				},
			)
		} else {
			tcam_key := uint32((ipsetID & 0xFFFF << 8) | (0 & 0xFF))

			tableName = "k8s_dp_control.acl_lpm_root_lut_ingress"
			entryDelete = p4RtC.NewTableEntry(
				"k8s_dp_control.acl_lpm_root_lut_ingress",
				map[string]client.MatchInterface{
					"user_meta.gmeta.tcam_key": &client.TernaryMatch{
						Value: ToBytes(tcam_key),
						Mask:  ToBytes(uint32(0xFFFFFFFF)),
					},
				},
				nil,
				&client.TableEntryOptions{
					IdleTimeout: 0,
					Priority:    int32(priority),
				},
			)
		}
		if err := p4RtC.DeleteTableEntry(ctx, entryDelete); err != nil {
			log.Errorf("Cannot delete entry from %s: %v", tableName, err)
			return err
		}

	default:
		log.Warnf("Invalid action %v", action)
		err := fmt.Errorf("Invalid action %v", action)
		return err
	}

	return nil
}

func AclIpSetMatchTable(ctx context.Context, p4RtC *client.Client,
	ipsetID uint16, cidr string, ipset_bitmap uint8, direction string, action InterfaceType) error {
	var tableName string
	var entryAdd *p4_v1.TableEntry
	var entryDelete *p4_v1.TableEntry

	res := strings.Split(cidr, "/")
	ip := res[0]
	plen, err := strconv.Atoi(res[1])
	if err != nil {
		log.Errorf("Invalid cidr %s: err: %v", cidr, err)
		return err
	}

	lpmRoot := ipsetID

	switch action {
	case Insert:
		if direction == "TX" {
			tableName = "k8s_dp_control.acl_ipset_match_table_egress"
			entryAdd = p4RtC.NewTableEntry(
				"k8s_dp_control.acl_ipset_match_table_egress",
				map[string]client.MatchInterface{
					"ipset_table_lpm_root_egress": &client.ExactMatch{
						Value: ToBytes(lpmRoot),
					},
					"hdrs.ipv4[meta.common.depth].dst_ip": &client.LpmMatch{
						Value: Pack32BinaryIP4(string(ip)),
						PLen:  int32(plen),
					},
				},
				p4RtC.NewTableActionDirect("k8s_dp_control.set_ipset_match_result",
					[][]byte{ToBytes(ipset_bitmap)}),
				nil,
			)
		} else {
			tableName = "k8s_dp_control.acl_ipset_match_table_ingress"
			entryAdd = p4RtC.NewTableEntry(
				"k8s_dp_control.acl_ipset_match_table_ingress",
				map[string]client.MatchInterface{
					"ipset_table_lpm_root_ingress": &client.ExactMatch{
						Value: ToBytes(lpmRoot),
					},
					"hdrs.ipv4[meta.common.depth].src_ip": &client.LpmMatch{
						Value: Pack32BinaryIP4(string(ip)),
						PLen:  int32(plen),
					},
				},
				p4RtC.NewTableActionDirect("k8s_dp_control.set_ipset_match_result",
					[][]byte{ToBytes(ipset_bitmap)}),
				nil,
			)
		}
		if err := p4RtC.InsertTableEntry(ctx, entryAdd); err != nil {
			log.Errorf("Cannot insert entry into %s: %v", tableName, err)
			return err
		}

	case Delete:
		tableName = "k8s_dp_control.acl_ipset_match_table_egress"
		if direction == "TX" {
			tableName = "k8s_dp_control.acl_ipset_match_table_egress"
			entryDelete = p4RtC.NewTableEntry(
				"k8s_dp_control.acl_ipset_match_table_egress",
				map[string]client.MatchInterface{
					"ipset_table_lpm_root_egress": &client.ExactMatch{
						Value: ToBytes(lpmRoot),
					},
					"hdrs.ipv4[meta.common.depth].dst_ip": &client.LpmMatch{
						Value: Pack32BinaryIP4(string(ip)),
						PLen:  int32(plen),
					},
				},
				nil,
				nil,
			)
		} else {
			tableName = "k8s_dp_control.acl_ipset_match_table_ingress"
			entryDelete = p4RtC.NewTableEntry(
				"k8s_dp_control.acl_ipset_match_table_ingress",
				map[string]client.MatchInterface{
					"ipset_table_lpm_root_ingress": &client.ExactMatch{
						Value: ToBytes(lpmRoot),
					},
					"hdrs.ipv4[meta.common.depth].src_ip": &client.LpmMatch{
						Value: Pack32BinaryIP4(string(ip)),
						PLen:  int32(plen),
					},
				},
				nil,
				nil,
			)
		}
		if err := p4RtC.DeleteTableEntry(ctx, entryDelete); err != nil {
			log.Errorf("Cannot delete entry from %s: %v", tableName, err)
			return err
		}

	default:
		log.Warnf("Invalid action %v", action)
		err := fmt.Errorf("Invalid action %v", action)
		return err
	}

	return nil
}

func DstPortRcTable(ctx context.Context, p4RtC *client.Client,
	rangeID uint16, portrange []uint16, protocol uint8,
	action InterfaceType) error {
	var tableName string
	var entry *p4_v1.TableEntry
	var entryDelete *p4_v1.TableEntry
	var ports = [][]byte{}

	for i := range portrange {
		ports = append(ports, ToBytes(portrange[i]))
	}

	if protocol == PROTO_TCP {
		tableName = "k8s_dp_control.tcp_dport_rc_table"
		entry = p4RtC.NewTableEntry(
			"k8s_dp_control.tcp_dport_rc_table",
			map[string]client.MatchInterface{
				"meta.common.range_idx": &client.ExactMatch{
					Value: ToBytes(rangeID),
				},
			},
			p4RtC.NewTableActionDirect("k8s_dp_control.do_range_check_tcp", ports),
			nil,
		)
	}
	if protocol == PROTO_UDP {
		tableName = "k8s_dp_control.udp_dport_rc_table"
		entry = p4RtC.NewTableEntry(
			"k8s_dp_control.udp_dport_rc_table",
			map[string]client.MatchInterface{
				"meta.common.range_idx": &client.ExactMatch{
					Value: ToBytes(rangeID),
				},
			},
			p4RtC.NewTableActionDirect("k8s_dp_control.do_range_check_udp", ports),
			nil,
		)
	}

	switch action {
	case Insert:
		if err := p4RtC.InsertTableEntry(ctx, entry); err != nil {
			log.Errorf("Cannot insert entry into %s: %v", tableName, err)
			return err
		}

	case Update:
		if err := p4RtC.ModifyTableEntry(ctx, entry); err != nil {
			log.Errorf("Cannot update entry to %s: %v", tableName, err)
			return err
		}

	case Delete:
		if protocol == PROTO_TCP {
			tableName = "k8s_dp_control.tcp_dport_rc_table"
			entryDelete = p4RtC.NewTableEntry(
				"k8s_dp_control.tcp_dport_rc_table",
				map[string]client.MatchInterface{
					"meta.common.range_idx": &client.ExactMatch{
						Value: ToBytes(rangeID),
					},
				},
				nil,
				nil,
			)
		}
		if protocol == PROTO_UDP {
			tableName = "k8s_dp_control.udp_dport_rc_table"
			entryDelete = p4RtC.NewTableEntry(
				"k8s_dp_control.udp_dport_rc_table",
				map[string]client.MatchInterface{
					"meta.common.range_idx": &client.ExactMatch{
						Value: ToBytes(rangeID),
					},
				},
				nil,
				nil,
			)
		}
		if err := p4RtC.DeleteTableEntry(ctx, entryDelete); err != nil {
			log.Errorf("Cannot delete entry from %s: %v", tableName, err)
			return err
		}

	default:
		log.Warnf("Invalid action %v", action)
		err := fmt.Errorf("Invalid action %v", action)
		return err
	}
	return nil
}

func IsSame(slice1 []uint16, slice2 []uint16) bool {
	if len(slice1) != len(slice2) {
		return false
	}
	for i := range slice1 {
		if slice1[i] != slice2[i] {
			log.Infof("%d and %d are not same", slice1[i], slice2[i])
			return false
		}
	}
	return true
}

func updatePolicy(ctx context.Context, p4RtC *client.Client,
	policy store.Policy, action InterfaceType) error {
	for id, ruleGroup := range policy.RuleGroups {
		if err := AclLpmRootLutTable(ctx, p4RtC, id, ruleGroup.Direction, action); err != nil {
			log.Errorf("Failed to add entry to AclLpmRootLutTable, err: %v", err)
			return err
		}

		for _, rule := range ruleGroup.Rules {
			cidr := rule.Cidr
			mask := rule.RuleMask

			if err := AclIpSetMatchTable(ctx, p4RtC, id, cidr, mask, ruleGroup.Direction,
				action); err != nil {
				log.Errorf("Failed to add entry to AclIpSetMatchTable, err: %v", err)
				return err
			}
		}
		if len(ruleGroup.DportRange) != 0 {
			if err := DstPortRcTable(ctx, p4RtC, id, ruleGroup.DportRange, ruleGroup.Protocol,
				action); err != nil {
				log.Errorf("Failed to add entry into DstPortRcTable, err: %v", err)
				return err
			}
		}
		//if action == Delete {
		//	for _, epName := range policy.WorkerEps {
		//		if epEntry := store.GetWorkerEp(epName); epEntry != nil {
		//			ep := epEntry.(store.PolicyWorkerEndPoint)
		//			if err := updateWorkload(ctx, p4RtC, ep, Delete); err != nil {
		//				return err
		//			}
		//			policy.DeleteWorkerEp(epName)
		//		}
		//	}
		//}
		/*
			Release rule group index back to stack.
		*/
		if action == Delete {
			store.ReleaseRuleGroupId(int(ruleGroup.Index))
		}

	}
	return nil
}

func updateWorkloadRules(ctx context.Context, p4RtC *client.Client, ip string,
	direction string, ruleGroups map[uint16]store.RuleGroup, action InterfaceType) error {
	noProtoRuleProcessed := false
	for id, ruleGroup := range ruleGroups {
		if ruleGroup.Direction == direction {
			if err := AclPodIpProtoTable(ctx, p4RtC, ruleGroup.Protocol, ip,
				id, id, ruleGroup.Direction, action); err != nil {
				log.Errorf("Failed to %s entry from AclPodIpProtoTable, err: %v", GetStr(action), err)
				return err
			}
			if ruleGroup.Protocol == 0 {
				noProtoRuleProcessed = true
			}
		}
	}

	if noProtoRuleProcessed == false {
		if err := AclPodIpTableDenyAll(ctx, p4RtC, 0, ip, direction, action); err != nil {
			log.Errorf("Failed to %s DenyAll entry from AclPodIpTable, err: %v", GetStr(action), err)
			return err
		}
	}

	return nil
}

func updateWorkloadPolicies(ctx context.Context, p4RtC *client.Client,
	policies []string, ip, ep, direction string, action InterfaceType) error {
	for _, pName := range policies {
		if pEntry := store.GetPolicy(pName); pEntry != nil {
			policy := pEntry.(store.Policy)
			if err := updateWorkloadRules(ctx, p4RtC, ip, direction,
				policy.RuleGroups, action); err != nil {
				return err
			}
			switch action {
			case Insert:
				policy.AddWorkerEp(ep)
			case Delete:
				policy.DeleteWorkerEp(ep)
			default:
				log.Errorf("Invalid action type: %v", action)
				return fmt.Errorf("Invalid action type: %v", action)
			}
		}
	}
	return nil
}

func updateWorkload(ctx context.Context, p4RtC *client.Client,
	ep store.PolicyWorkerEndPoint, action InterfaceType) error {
	if err := updateWorkloadPolicies(ctx, p4RtC, ep.PolicyNameIngress,
		ep.WorkerIp, ep.WorkerEp, "RX", action); err != nil {
		return err
	}
	if err := updateWorkloadPolicies(ctx, p4RtC, ep.PolicyNameEgress,
		ep.WorkerIp, ep.WorkerEp, "TX", action); err != nil {
		return err
	}

	return nil
}

func addWorkload(ctx context.Context, p4RtC *client.Client,
	ep store.PolicyWorkerEndPoint) error {
	for _, policyname := range ep.PolicyNameIngress {
		policy := store.PolicySet.PolicyMap[policyname]
		for id, RuleGroup := range policy.RuleGroups {
			if RuleGroup.Direction == "RX" {
				if err := AclPodIpProtoTable(ctx, p4RtC, RuleGroup.Protocol, ep.WorkerIp,
					id, id, "RX", Insert); err != nil {
					log.Errorf("Failed to add entry to AclPodIpProtoTable, err: %v", err)
					return err
				}
			}
		}
	}

	for _, policyname := range ep.PolicyNameEgress {
		policy := store.PolicySet.PolicyMap[policyname]
		for id, RuleGroup := range policy.RuleGroups {
			if RuleGroup.Direction == "TX" {
				if err := AclPodIpProtoTable(ctx, p4RtC, RuleGroup.Protocol, ep.WorkerIp,
					id, id, "TX", Insert); err != nil {
					log.Errorf("Failed to add entry to AclPodIpProtoTable, err: %v", err)
					return err
				}
			}
		}
	}
	return nil
}

func PolicyTableEntries(ctx context.Context, p4RtC *client.Client, tbltype OperationType, in interface{}) error {
	switch tbltype {
	case PolicyAdd:
		policy := in.(store.Policy)

		/*
			If exists, delete policy
		*/
		if pEntry := policy.GetFromStore(); pEntry != nil {
			oldPolicy := pEntry.(store.Policy)
			if err := updatePolicy(ctx, p4RtC, oldPolicy, Delete); err != nil {
				log.Errorf("Failed to delete old entries of the policy %v, err: %v", oldPolicy, err)
				return err
			}
		}
		return updatePolicy(ctx, p4RtC, policy, Insert)

	case PolicyDel:
		return updatePolicy(ctx, p4RtC, in.(store.Policy), Delete)

	case WorkloadAdd:
		ep := in.(store.PolicyWorkerEndPoint)

		ctx = context.Background()
		if oldEntry := ep.GetFromStore(); oldEntry != nil {
			oldEp := oldEntry.(store.PolicyWorkerEndPoint)

			/*
				Delete any stale policies and retain the existing policies
			*/
			staleIngress := utils.StrDiff(oldEp.PolicyNameIngress, ep.PolicyNameIngress)
			staleEgress := utils.StrDiff(oldEp.PolicyNameEgress, ep.PolicyNameEgress)
			if len(staleIngress) > 0 || len(staleEgress) > 0 {
				oldEp.PolicyNameIngress = staleIngress
				oldEp.PolicyNameEgress = staleEgress
				updateWorkload(ctx, p4RtC, oldEp, Delete)
			}

			/*
				Apply new policies
			*/
			newIngress := utils.StrDiff(ep.PolicyNameIngress, oldEp.PolicyNameIngress)
			newEgress := utils.StrDiff(ep.PolicyNameEgress, oldEp.PolicyNameEgress)
			if len(newIngress) > 0 || len(newEgress) > 0 {
				ep.PolicyNameIngress = newIngress
				ep.PolicyNameEgress = newEgress
				return updateWorkload(ctx, p4RtC, ep, Insert)
			} else {
				/*
					No updates required. Return success
				*/
				return nil
			}

		} else {
			/*
				No old policies applied. Apply all policies to the
				worker endpoint.
			*/
			return updateWorkload(ctx, p4RtC, ep, Insert)
		}

	case WorkloadDel:
		ep := in.(store.PolicyWorkerEndPoint)
		return updateWorkload(ctx, p4RtC, ep, Delete)

	default:
		return errors.New("Invalid operation type")
	}
}

func UpdatePolicyDefaultEntries(ctx context.Context, p4RtC *client.Client, checkAclResultEntries [][]byte, action InterfaceType) error {
	var aclAction string

	for i := 0; i < len(checkAclResultEntries); i++ {
		if checkAclResultEntries[i][6] == 1 {
			aclAction = "allow"
		} else {
			aclAction = "deny"
		}
		err := CheckAclResult(ctx, p4RtC, checkAclResultEntries[i][0], checkAclResultEntries[i][1], checkAclResultEntries[i][2],
			checkAclResultEntries[i][3], checkAclResultEntries[i][4], uint16(checkAclResultEntries[i][5]), aclAction, action)
		if err != nil {
			return err
		}
	}
	return nil

}
