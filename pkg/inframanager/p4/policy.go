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
	"strconv"
	"strings"
	//	"net"
)

type operationType int

const (
	denyAll operationType = iota
	policyAdd
	policyDel
	policyUpdate
	workloadAdd
	workloadUpdate
	workloadDel
	ipsetAdd
	ipsetUpdate
	ipsetDel
)

func AclPodIpProtoTable(ctx context.Context, p4RtC *client.Client,
	protocol uint8, workerep string, polID uint16, rangeID uint16, direction string,
	action InterfaceType) error {
	var tableName string
	var entryAdd *p4_v1.TableEntry
	var entryDelete *p4_v1.TableEntry
	switch action {
	case Insert:
		if direction == "TX" {
			tableName = "k8s_dp_control.acl_pod_ip_proto_table_egress"
			if protocol != 0 {
				entryAdd = p4RtC.NewTableEntry(
					"k8s_dp_control.acl_pod_ip_proto_table_egress",
					map[string]client.MatchInterface{
						"hdr.ipv4.src_addr": &client.ExactMatch{
							Value: Pack32BinaryIP4(workerep),
						},
						"hdr.ipv4.protocol": &client.LpmMatch{
							Value: valueToBytes8(protocol),
							PLen:  8,
						},
					},
					p4RtC.NewTableActionDirect("k8s_dp_control.set_range_check_ref",
						[][]byte{valueToBytes16(polID),
							valueToBytes16(rangeID)}),
					nil,
				)
			} else {
				entryAdd = p4RtC.NewTableEntry(
					"k8s_dp_control.acl_pod_ip_proto_table_egress",
					map[string]client.MatchInterface{
						"hdr.ipv4.src_addr": &client.ExactMatch{
							Value: Pack32BinaryIP4(workerep),
						},
						"hdr.ipv4.protocol": &client.LpmMatch{
							Value: valueToBytes8(0),
							PLen:  0,
						},
					},
					p4RtC.NewTableActionDirect("k8s_dp_control.set_status_match_ipset_only",
						[][]byte{valueToBytes16(polID)}),
					nil,
				)
			}
			if err := p4RtC.InsertTableEntry(ctx, entryAdd); err != nil {
				log.Errorf("Cannot insert entry into %s: %v", tableName, err)
				return err
			}
		} else {
			tableName = "k8s_dp_control.acl_pod_ip_proto_table_ingress"
			if protocol != 0 {
				entryAdd = p4RtC.NewTableEntry(
					"k8s_dp_control.acl_pod_ip_proto_table_ingress",
					map[string]client.MatchInterface{
						"hdr.ipv4.dst_addr": &client.ExactMatch{
							Value: Pack32BinaryIP4(workerep),
						},
						"hdr.ipv4.protocol": &client.LpmMatch{
							Value: valueToBytes8(protocol),
							PLen:  8,
						},
					},
					p4RtC.NewTableActionDirect("k8s_dp_control.set_range_check_ref",
						[][]byte{valueToBytes16(polID),
							valueToBytes16(rangeID)}),
					nil,
				)
			} else {
				entryAdd = p4RtC.NewTableEntry(
					"k8s_dp_control.acl_pod_ip_proto_table_ingress",
					map[string]client.MatchInterface{
						"hdr.ipv4.dst_addr": &client.ExactMatch{
							Value: Pack32BinaryIP4(workerep),
						},
						"hdr.ipv4.protocol": &client.LpmMatch{
							Value: valueToBytes8(0),
							PLen:  0,
						},
					},
					p4RtC.NewTableActionDirect("k8s_dp_control.set_status_match_ipset_only",
						[][]byte{valueToBytes16(polID)}),
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
			tableName = "k8s_dp_control.acl_pod_ip_proto_table_egress"
			if protocol != 0 {
				entryDelete = p4RtC.NewTableEntry(
					"k8s_dp_control.acl_pod_ip_proto_table_egress",
					map[string]client.MatchInterface{
						"hdr.ipv4.src_addr": &client.ExactMatch{
							Value: Pack32BinaryIP4(workerep),
						},
						"hdr.ipv4.protocol": &client.LpmMatch{
							Value: valueToBytes8(protocol),
							PLen:  8,
						},
					},
					nil,
					nil,
				)
			} else {
				entryDelete = p4RtC.NewTableEntry(
					"k8s_dp_control.acl_pod_ip_proto_table_egress",
					map[string]client.MatchInterface{
						"hdr.ipv4.src_addr": &client.ExactMatch{
							Value: Pack32BinaryIP4(workerep),
						},
						"hdr.ipv4.protocol": &client.LpmMatch{
							Value: valueToBytes8(0),
							PLen:  0,
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
			tableName = "k8s_dp_control.acl_pod_ip_proto_table_ingress"
			if protocol != 0 {
				entryDelete = p4RtC.NewTableEntry(
					"k8s_dp_control.acl_pod_ip_proto_table_ingress",
					map[string]client.MatchInterface{
						"hdr.ipv4.dst_addr": &client.ExactMatch{
							Value: Pack32BinaryIP4(workerep),
						},
						"hdr.ipv4.protocol": &client.LpmMatch{
							Value: valueToBytes8(protocol),
							PLen:  8,
						},
					},
					nil,
					nil,
				)
			} else {
				entryDelete = p4RtC.NewTableEntry(
					"k8s_dp_control.acl_pod_ip_proto_table_ingress",
					map[string]client.MatchInterface{
						"hdr.ipv4.dst_addr": &client.ExactMatch{
							Value: Pack32BinaryIP4(workerep),
						},
						"hdr.ipv4.protocol": &client.LpmMatch{
							Value: valueToBytes8(0),
							PLen:  0,
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

func AclIpSetMatchTable(ctx context.Context, p4RtC *client.Client,
	polID uint16, cidr string, mask uint8, direction string, action InterfaceType) error {
	res := strings.Split(cidr, "/")
	ip := res[0]
	plen, _ := strconv.Atoi(res[1])
	var tableName string
	var entryAdd *p4_v1.TableEntry
	var entryDelete *p4_v1.TableEntry
	switch action {
	case Insert:
		if direction == "TX" {
			tableName = "k8s_dp_control.acl_ipset_match_table_egress"
			entryAdd = p4RtC.NewTableEntry(
				"k8s_dp_control.acl_ipset_match_table_egress",
				map[string]client.MatchInterface{
					"meta.acl_pol_id": &client.ExactMatch{
						Value: valueToBytes16(polID),
					},
					"hdr.ipv4.dst_addr": &client.LpmMatch{
						Value: Pack32BinaryIP4(ip),
						PLen:  int32(plen),
					},
				},
				p4RtC.NewTableActionDirect("k8s_dp_control.set_ipset_match_result",
					[][]byte{valueToBytes8(mask)}),
				nil,
			)
		} else {
			tableName = "k8s_dp_control.acl_ipset_match_table_ingress"
			entryAdd = p4RtC.NewTableEntry(
				"k8s_dp_control.acl_ipset_match_table_ingress",
				map[string]client.MatchInterface{
					"meta.acl_pol_id": &client.ExactMatch{
						Value: valueToBytes16(polID),
					},
					"hdr.ipv4.src_addr": &client.LpmMatch{
						Value: Pack32BinaryIP4(ip),
						PLen:  int32(plen),
					},
				},
				p4RtC.NewTableActionDirect("k8s_dp_control.set_ipset_match_result",
					[][]byte{valueToBytes8(mask)}),
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
					"meta.acl_pol_id": &client.ExactMatch{
						Value: valueToBytes16(polID),
					},
					"hdr.ipv4.dst_addr": &client.LpmMatch{
						Value: Pack32BinaryIP4(ip),
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
					"meta.acl_pol_id": &client.ExactMatch{
						Value: valueToBytes16(polID),
					},
					"hdr.ipv4.src_addr": &client.LpmMatch{
						Value: Pack32BinaryIP4(ip),
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
	polID uint16, portrange []uint16, protocol uint8,
	action InterfaceType) error {
	var tableName string
	var entry *p4_v1.TableEntry
	var entryDelete *p4_v1.TableEntry

	if protocol == 6 {
		tableName = "k8s_dp_control.tcp_dport_rc_table"
		entry = p4RtC.NewTableEntry(
			"k8s_dp_control.tcp_dport_rc_table",
			map[string]client.MatchInterface{
				"meta.acl_pol_id": &client.ExactMatch{
					Value: valueToBytes16(polID),
				},
			},
			p4RtC.NewTableActionDirect("k8s_dp_control.do_range_check_tcp",
				[][]byte{valueToBytes16(portrange[0]),
					valueToBytes16(portrange[1]),
					valueToBytes16(portrange[2]),
					valueToBytes16(portrange[3]),
					valueToBytes16(portrange[4]),
					valueToBytes16(portrange[5]),
					valueToBytes16(portrange[6]),
					valueToBytes16(portrange[7]),
					valueToBytes16(portrange[8]),
					valueToBytes16(portrange[9]),
					valueToBytes16(portrange[10]),
					valueToBytes16(portrange[11]),
					valueToBytes16(portrange[12]),
					valueToBytes16(portrange[13]),
					valueToBytes16(portrange[14]),
					valueToBytes16(portrange[15])}),
			nil,
		)
	}
	if protocol == 17 {
		tableName = "k8s_dp_control.udp_dport_rc_table"
		entry = p4RtC.NewTableEntry(
			"k8s_dp_control.udp_dport_rc_table",
			map[string]client.MatchInterface{
				"meta.acl_pol_id": &client.ExactMatch{
					Value: valueToBytes16(polID),
				},
			},
			p4RtC.NewTableActionDirect("k8s_dp_control.do_range_check_udp",
				[][]byte{valueToBytes16(portrange[0]),
					valueToBytes16(portrange[1]),
					valueToBytes16(portrange[2]),
					valueToBytes16(portrange[3]),
					valueToBytes16(portrange[4]),
					valueToBytes16(portrange[5]),
					valueToBytes16(portrange[6]),
					valueToBytes16(portrange[7]),
					valueToBytes16(portrange[8]),
					valueToBytes16(portrange[9]),
					valueToBytes16(portrange[10]),
					valueToBytes16(portrange[11]),
					valueToBytes16(portrange[12]),
					valueToBytes16(portrange[13]),
					valueToBytes16(portrange[14]),
					valueToBytes16(portrange[15])}),
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
		if protocol == 6 {
			tableName = "k8s_dp_control.tcp_dport_rc_table"
			entryDelete = p4RtC.NewTableEntry(
				"k8s_dp_control.tcp_dport_rc_table",
				map[string]client.MatchInterface{
					"meta.acl_pol_id": &client.ExactMatch{
						Value: valueToBytes16(polID),
					},
				},
				nil,
				nil,
			)
		}
		if protocol == 17 {
			tableName = "k8s_dp_control.udp_dport_rc_table"
			entryDelete = p4RtC.NewTableEntry(
				"k8s_dp_control.udp_dport_rc_table",
				map[string]client.MatchInterface{
					"meta.acl_pol_id": &client.ExactMatch{
						Value: valueToBytes16(polID),
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

func IsNamePresent(substr string, strslice []string) bool {
	for _, str := range strslice {
		if strings.Contains(str, substr) {
			return true
		}
	}
	log.Infof("name %s is not present in given slice", substr)
	return false
}

func IsSame(slice1 []uint16, slice2 []uint16) bool {
	for i := range slice1 {
		if slice1[i] != slice2[i] {
			log.Infof("%d and %d are not same", slice1[i], slice2[i])
			return false
		}
	}
	return true
}

func PolicyTableEntries(ctx context.Context, p4RtC *client.Client, tbltype operationType, policy *store.Policy, workloadep *store.PolicyWorkerEndPoint) error {
	var err error
	switch tbltype {
	case policyAdd:
		for ipsetidx, _ := range policy.IpSetIDx {
			for ruleid, _ := range policy.IpSetIDx[ipsetidx].RuleID {
				cidr := policy.IpSetIDx[ipsetidx].RuleID[ruleid].Cidr
				mask := policy.IpSetIDx[ipsetidx].RuleID[ruleid].RuleMask
				err = AclIpSetMatchTable(ctx, p4RtC, ipsetidx, cidr, mask, policy.IpSetIDx[ipsetidx].Direction, Insert)
				if err != nil {
					log.Errorf("AclIpSetMatchTable failed %v", err)
				} else {
					log.Infof("AclIpSetMatchTable passed")
				}
			}
			if len(policy.IpSetIDx[ipsetidx].DportRange) != 0 {
				err = DstPortRcTable(ctx, p4RtC, ipsetidx, policy.IpSetIDx[ipsetidx].DportRange, policy.IpSetIDx[ipsetidx].Protocol, Insert)
				if err != nil {
					log.Errorf("DstPortRcTable failed %v", err)
				} else {
					log.Infof("DstPortRcTable passed")
				}
			}
		}
		fmt.Println("Inserted policy entry into pipeline", policy)

	case policyDel:
		for ipsetidx, _ := range policy.IpSetIDx {
			for ruleid, _ := range policy.IpSetIDx[ipsetidx].RuleID {
				cidr := policy.IpSetIDx[ipsetidx].RuleID[ruleid].Cidr
				err = AclIpSetMatchTable(ctx, p4RtC, ipsetidx, cidr, 0, policy.IpSetIDx[ipsetidx].Direction, Delete)
				if err != nil {
					log.Errorf("AclIpSetMatchTable failed %v", err)
				} else {
					log.Infof("AclIpSetMatchTable passed")
				}
			}
			if len(policy.IpSetIDx[ipsetidx].DportRange) != 0 {
				err = DstPortRcTable(ctx, p4RtC, ipsetidx, nil, policy.IpSetIDx[ipsetidx].Protocol, Delete)
				if err != nil {
					log.Errorf("DstPortRcTable failed %v", err)
				} else {
					log.Infof("DstPortRcTable passed")
				}
			}
		}
		fmt.Println("deleted policy entry", policy)

	case policyUpdate:
		policyOld := store.PolicySet.PolicyMap[policy.PolicyName]
		oldrules := make([]string, 0)
		newrules := make([]string, 0)
		var index int
		//create slice of existing rules
		for ipsetidx, _ := range policyOld.IpSetIDx {
			for ruleid, _ := range policyOld.IpSetIDx[ipsetidx].RuleID {
				oldrules = append(oldrules, ruleid)
			}
		}
		log.Infof("old rules: %s", oldrules)
		//create slice of new rules
		for ipsetidx, _ := range policy.IpSetIDx {
			for ruleid, _ := range policy.IpSetIDx[ipsetidx].RuleID {
				newrules = append(newrules, ruleid)
			}
		}
		log.Infof("new rules: %s", newrules)
		log.Infof("delete old rules if its not part of updated set of rules")
		for ipsetidx, _ := range policyOld.IpSetIDx {
			dportRng := make([]uint16, 16)
			for ruleid, _ := range policyOld.IpSetIDx[ipsetidx].RuleID {
				index++
				if IsNamePresent(ruleid, newrules) {
					if len(policyOld.IpSetIDx[ipsetidx].RuleID[ruleid].PortRange) != 0 {
						i := index
						j := i + 1
						dportRng[i] = policyOld.IpSetIDx[ipsetidx].RuleID[ruleid].PortRange[0]
						dportRng[j] = policyOld.IpSetIDx[ipsetidx].RuleID[ruleid].PortRange[1]
					}
				} else { //if rule is not present, then delete only that rule from pipeline
					if len(policyOld.IpSetIDx[ipsetidx].RuleID[ruleid].PortRange) != 0 {
						i := index
						j := i + 1
						dportRng[i] = 0
						dportRng[j] = 0
					}
					cidr := policyOld.IpSetIDx[ipsetidx].RuleID[ruleid].Cidr
					err = AclIpSetMatchTable(ctx, p4RtC, ipsetidx, cidr, 0, policyOld.IpSetIDx[ipsetidx].Direction, Delete)
					if err != nil {
						log.Errorf("AclIpSetMatchTable failed %v", err)
					} else {
						log.Infof("AclIpSetMatchTable passed")
					}
				}
			}
			index = 0
			fmt.Println("port range is:", dportRng)
			if len(dportRng) == 0 {
				err = DstPortRcTable(ctx, p4RtC, ipsetidx, nil, policyOld.IpSetIDx[ipsetidx].Protocol, Delete)
				if err != nil {
					log.Errorf("DstPortRcTable failed %v", err)
				} else {
					log.Infof("DstPortRcTable passed")
				}
			} else {
				err = DstPortRcTable(ctx, p4RtC, ipsetidx, dportRng, policyOld.IpSetIDx[ipsetidx].Protocol, Update)
				if err != nil {
					log.Errorf("DstPortRcTable failed %v", err)
				} else {
					log.Infof("DstPortRcTable passed")
				}
			}
		}
		//add newly added rules to the pipeline
		for ipsetidx, _ := range policy.IpSetIDx {
			dportRng := make([]uint16, 16)
			for ruleid, _ := range policy.IpSetIDx[ipsetidx].RuleID {
				index++
				if IsNamePresent(ruleid, oldrules) {
					if len(policy.IpSetIDx[ipsetidx].RuleID[ruleid].PortRange) != 0 {
						i := index
						j := i + 1
						dportRng[i] = policy.IpSetIDx[ipsetidx].RuleID[ruleid].PortRange[0]
						dportRng[j] = policy.IpSetIDx[ipsetidx].RuleID[ruleid].PortRange[1]
					}
				} else { //if rule is not present, then insert only that rule to pipeline
					if len(policy.IpSetIDx[ipsetidx].RuleID[ruleid].PortRange) != 0 {
						i := index
						j := i + 1
						dportRng[i] = policy.IpSetIDx[ipsetidx].RuleID[ruleid].PortRange[0]
						dportRng[j] = policy.IpSetIDx[ipsetidx].RuleID[ruleid].PortRange[1]
					}
					cidr := policy.IpSetIDx[ipsetidx].RuleID[ruleid].Cidr
					mask := policy.IpSetIDx[ipsetidx].RuleID[ruleid].RuleMask
					err = AclIpSetMatchTable(ctx, p4RtC, ipsetidx, cidr, mask, policy.IpSetIDx[ipsetidx].Direction, Delete)
					if err != nil {
						log.Errorf("AclIpSetMatchTable failed %v", err)
					} else {
						log.Infof("AclIpSetMatchTable passed")
					}
				}
			}
			index = 0
			fmt.Println("port range:", dportRng)
			if len(dportRng) != 0 {
				if len(policyOld.IpSetIDx[ipsetidx].DportRange) == 0 { //if new rule has port range and previously we have not added any port range for same ipsetidx, then insert port range for that ipsetidx
					err = DstPortRcTable(ctx, p4RtC, ipsetidx, dportRng, policy.IpSetIDx[ipsetidx].Protocol, Insert)
					if err != nil {
						log.Errorf("DstPortRcTable failed %v", err)
					} else {
						log.Infof("DstPortRcTable passed")
					}
				}
			} else if len(dportRng) != 0 && len(policyOld.IpSetIDx[ipsetidx].DportRange) != 0 { //if old port range and new port range for a ipsetidx are different
				if !IsSame(dportRng, policyOld.IpSetIDx[ipsetidx].DportRange) {
					err = DstPortRcTable(ctx, p4RtC, ipsetidx, dportRng, policy.IpSetIDx[ipsetidx].Protocol, Update)
					if err != nil {
						log.Errorf("DstPortRcTable failed %v", err)
					} else {
						log.Infof("DstPortRcTable passed")
					}
				}
			} else {
			}
		}
		fmt.Println("updated policy:", policy)

	case workloadAdd:
		for _, policyname := range workloadep.PolicyNameIngress {
			policy := store.PolicySet.PolicyMap[policyname]
			for ipsetidx, _ := range policy.IpSetIDx {
				err = AclPodIpProtoTable(ctx, p4RtC, policy.IpSetIDx[ipsetidx].Protocol, workloadep.WorkerEp, ipsetidx, ipsetidx, "RX", Insert)
				if err != nil {
					log.Errorf("AclPodIpProtoTable failed %v", err)
				} else {
					log.Infof("AclPodIpProtoTable passed")
				}
			}
		}

		for _, policyname := range workloadep.PolicyNameEgress {
			policy := store.PolicySet.PolicyMap[policyname]
			for ipsetidx, _ := range policy.IpSetIDx {
				err = AclPodIpProtoTable(ctx, p4RtC, policy.IpSetIDx[ipsetidx].Protocol, workloadep.WorkerEp, ipsetidx, ipsetidx, "TX", Insert)
				if err != nil {
					log.Errorf("AclPodIpProtoTable failed %v", err)
				} else {
					log.Infof("AclPodIpProtoTable passed")
				}
			}
		}
		log.Infof("workloadep added: %s", workloadep)

	case workloadDel:
		for _, policyname := range workloadep.PolicyNameIngress {
			policy := store.PolicySet.PolicyMap[policyname]
			for ipsetidx, _ := range policy.IpSetIDx {
				err = AclPodIpProtoTable(ctx, p4RtC, policy.IpSetIDx[ipsetidx].Protocol, workloadep.WorkerEp, ipsetidx, ipsetidx, "RX", Delete)
				if err != nil {
					log.Errorf("AclPodIpProtoTable failed %v", err)
				} else {
					log.Infof("AclPodIpProtoTable passed")
				}
			}
		}

		for _, policyname := range workloadep.PolicyNameEgress {
			policy := store.PolicySet.PolicyMap[policyname]
			for ipsetidx, _ := range policy.IpSetIDx {
				err = AclPodIpProtoTable(ctx, p4RtC, policy.IpSetIDx[ipsetidx].Protocol, workloadep.WorkerEp, ipsetidx, ipsetidx, "TX", Delete)
				if err != nil {
					log.Errorf("AclPodIpProtoTable failed %v", err)
				} else {
					log.Infof("AclPodIpProtoTable passed")
				}
			}
		}
		log.Infof("workload deleted: %s", workloadep)

	case workloadUpdate:
		workloadepold := store.PolicySet.WorkerEpMap[workloadep.WorkerEp]
		//ingress policy names
		//delete from policy tables for removed policies
		for _, policyname := range workloadepold.PolicyNameIngress {
			if !IsNamePresent(policyname, workloadep.PolicyNameIngress) { //if policyname from old store entry is not present in new entry, then delete
				policydel := store.PolicySet.PolicyMap[policyname]
				for ipsetidx, _ := range policydel.IpSetIDx {
					err = AclPodIpProtoTable(ctx, p4RtC, policydel.IpSetIDx[ipsetidx].Protocol, workloadep.WorkerEp, 0, 0, "RX", Delete)
					if err != nil {
						log.Errorf("AclPodIpProtoTable failed %v", err)
					} else {
						log.Infof("AclPodIpProtoTable passed")
					}
				}
			}
		}
		//insert to policy tables the new policies
		for _, policyname := range workloadep.PolicyNameIngress {
			if !IsNamePresent(policyname, workloadepold.PolicyNameIngress) {
				policyadd := store.PolicySet.PolicyMap[policyname]
				for ipsetidx, _ := range policyadd.IpSetIDx {
					err = AclPodIpProtoTable(ctx, p4RtC, policyadd.IpSetIDx[ipsetidx].Protocol, workloadep.WorkerEp, ipsetidx, ipsetidx, "RX", Insert)
					if err != nil {
						log.Errorf("AclPodIpProtoTable failed %v", err)
					} else {
						log.Infof("AclPodIpProtoTable passed")
					}
				}
			}
		}

		//egress policy names
		//delete from policy tables for removed policies
		for _, policyname := range workloadepold.PolicyNameEgress {
			if !IsNamePresent(policyname, workloadep.PolicyNameEgress) { //if policyname from old store entry is not present in new entry, then delete
				policydel := store.PolicySet.PolicyMap[policyname]
				for ipsetidx, _ := range policydel.IpSetIDx {
					err = AclPodIpProtoTable(ctx, p4RtC, policydel.IpSetIDx[ipsetidx].Protocol, workloadep.WorkerEp, 0, 0, "TX", Delete)
					if err != nil {
						log.Errorf("AclPodIpProtoTable failed %v", err)
					} else {
						log.Infof("AclPodIpProtoTable passed")
					}
				}
			}
		}
		//insert to policy tables the new policies
		for _, policyname := range workloadep.PolicyNameEgress {
			if !IsNamePresent(policyname, workloadepold.PolicyNameEgress) {
				policyadd := store.PolicySet.PolicyMap[policyname]
				for ipsetidx, _ := range policyadd.IpSetIDx {
					err = AclPodIpProtoTable(ctx, p4RtC, policyadd.IpSetIDx[ipsetidx].Protocol, workloadep.WorkerEp, ipsetidx, ipsetidx, "TX", Insert)
					if err != nil {
						log.Errorf("AclPodIpProtoTable failed %v", err)
					} else {
						log.Infof("AclPodIpProtoTable passed")
					}
				}
			}
		}
		log.Infof("updated workloadep: %s", workloadep)
	}
	return nil
}
