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
	"errors"
	"fmt"
	"github.com/antoninbas/p4runtime-go-client/pkg/client"
	"github.com/ipdk-io/k8s-infra-offload/pkg/inframanager/store"
	p4_v1 "github.com/p4lang/p4runtime/go/p4/v1"
	log "github.com/sirupsen/logrus"
	"strconv"
	"strings"
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
						[][]byte{ValueToBytes16(polID),
							ValueToBytes16(rangeID)}),
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
						[][]byte{ValueToBytes16(polID)}),
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
						[][]byte{ValueToBytes16(polID),
							ValueToBytes16(rangeID)}),
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
						[][]byte{ValueToBytes16(polID)}),
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
						Value: ValueToBytes16(polID),
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
						Value: ValueToBytes16(polID),
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
						Value: ValueToBytes16(polID),
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
						Value: ValueToBytes16(polID),
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
	var ports = [][]byte{}

	for i := range portrange {
		ports = append(ports, ValueToBytes16(portrange[i]))
	}

	if protocol == PROTO_TCP {
		tableName = "k8s_dp_control.tcp_dport_rc_table"
		entry = p4RtC.NewTableEntry(
			"k8s_dp_control.tcp_dport_rc_table",
			map[string]client.MatchInterface{
				"meta.acl_pol_id": &client.ExactMatch{
					Value: ValueToBytes16(polID),
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
				"meta.acl_pol_id": &client.ExactMatch{
					Value: ValueToBytes16(polID),
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
		if protocol == 6 {
			tableName = "k8s_dp_control.tcp_dport_rc_table"
			entryDelete = p4RtC.NewTableEntry(
				"k8s_dp_control.tcp_dport_rc_table",
				map[string]client.MatchInterface{
					"meta.acl_pol_id": &client.ExactMatch{
						Value: ValueToBytes16(polID),
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
						Value: ValueToBytes16(polID),
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

func PolicyTableEntries(ctx context.Context, p4RtC *client.Client, tbltype OperationType, in interface{}) error {
	switch tbltype {
	case PolicyAdd:
		policy := in.(store.Policy)
		for ipSetIDXId, ipSetIDX := range policy.IpSetIDXs {
			for _, rule := range ipSetIDX.Rules {
				cidr := rule.Cidr
				mask := rule.RuleMask

				if err := AclIpSetMatchTable(ctx, p4RtC, ipSetIDXId, cidr, mask, ipSetIDX.Direction,
					Insert); err != nil {
					log.Errorf("Failed to add entry to AclIpSetMatchTable, err: %v", err)
					return err
				}
			}
			if len(ipSetIDX.DportRange) != 0 {
				if err := DstPortRcTable(ctx, p4RtC, ipSetIDXId, ipSetIDX.DportRange, ipSetIDX.Protocol,
					Insert); err != nil {
					log.Errorf("Failed to add entry into DstPortRcTable, err: %v", err)
					return err
				}
			}
		}
		return nil

	case PolicyDel:
		policy := in.(store.Policy)
		for ipSetIDXId, ipSetIDX := range policy.IpSetIDXs {
			for _, rule := range ipSetIDX.Rules {
				cidr := rule.Cidr
				if err := AclIpSetMatchTable(ctx, p4RtC, ipSetIDXId, cidr, 0, ipSetIDX.Direction,
					Delete); err != nil {
					log.Errorf("Failed to delete entry from AclIpSetMatchTable, err: %v", err)
					return err
				}
			}
			if len(ipSetIDX.DportRange) != 0 {
				if err := DstPortRcTable(ctx, p4RtC, ipSetIDXId, nil, ipSetIDX.Protocol,
					Delete); err != nil {
					log.Errorf("Failed to delete entry from DstPortRcTable,err: %v", err)
					return err
				}
			}
		}
		return nil

	case PolicyUpdate:
		policy := in.(store.Policy)

		oldRules := map[string]store.Rule{}
		newRules := map[string]store.Rule{}

		//create map of new rules
		for _, ipSetIDX := range policy.IpSetIDXs {
			for ruleID, rule := range ipSetIDX.Rules {
				newRules[ruleID] = rule
			}
		}

		policyEntry := policy.GetFromStore()
		policyOld := policyEntry.(store.Policy)

		i := 0

		/*
			Delete old stale rules.
		*/
		for ipSetIDXId, ipSetIDX := range policyOld.IpSetIDXs {
			dportRng := make([]uint16, 16)
			for ruleID, rule := range ipSetIDX.Rules {
				oldRules[ruleID] = rule

				/*
					If the rule is not present in the policy update request,
					delete the rule.
				*/
				if _, ok := newRules[ruleID]; !ok {
					dportRng[i], i = 0, i+1
					dportRng[i], i = 0, i+1

					cidr := rule.Cidr

					if err := AclIpSetMatchTable(ctx, p4RtC, ipSetIDXId, cidr, 0, ipSetIDX.Direction,
						Delete); err != nil {
						log.Errorf("Failed to delete entry from AclIpSetMatchTable, err: %v", err)
						return err
					}

				} else { // same rule exists in the policy update request
					if len(rule.PortRange) != 0 {
						dportRng[i], i = rule.PortRange[0], i+1
						dportRng[i], i = rule.PortRange[1], i+1
					}
				}
			}
			log.Infof("port range is: %v", dportRng)
			if len(dportRng) == 0 {
				if err := DstPortRcTable(ctx, p4RtC, ipSetIDXId, nil, ipSetIDX.Protocol,
					Delete); err != nil {
					log.Errorf("Failed to delete entry from DstPortRcTable, err %v", err)
					return err
				}
			} else {
				if err := DstPortRcTable(ctx, p4RtC, ipSetIDXId, dportRng, ipSetIDX.Protocol,
					Update); err != nil {
					log.Errorf("Failed to update entry in DstPortRcTable, err: %v", err)
					return err
				}
			}
		}

		i = 0
		for ipSetIDXId, ipSetIDX := range policy.IpSetIDXs {
			dportRng := make([]uint16, 16)
			for ruleID, rule := range ipSetIDX.Rules {
				// add new rules to the pipeline
				if _, ok := oldRules[ruleID]; !ok {
					dportRng[i], i = rule.PortRange[0], i+1
					dportRng[i], i = rule.PortRange[1], i+1

					cidr := rule.Cidr
					mask := rule.RuleMask

					if err := AclIpSetMatchTable(ctx, p4RtC, ipSetIDXId, cidr, mask, ipSetIDX.Direction,
						Insert); err != nil {
						log.Errorf("Failed to add entry to AclIpSetMatchTable, err: %v", err)
						return err
					}
				} else { // same rule exists in the policy update request
					if len(rule.PortRange) != 0 {
						dportRng[i], i = rule.PortRange[0], i+1
						dportRng[i], i = rule.PortRange[1], i+1
					}
				}
			}
			log.Infof("port range is: %v", dportRng)

			/*
				If new rule has port range and previously we have not added any port range for same ipsetidx,
				then insert port range for that ipsetidx
			*/
			if len(policyOld.IpSetIDXs[ipSetIDXId].DportRange) == 0 {
				if err := DstPortRcTable(ctx, p4RtC, ipSetIDXId, dportRng, ipSetIDX.Protocol,
					Insert); err != nil {
					log.Errorf("Failed to add entry to DstPortRcTable, err: %v", err)
					return err
				}
			} else {
				/*
					If old port range and new port range for a ipsetidx are different
				*/
				if !IsSame(dportRng, policyOld.IpSetIDXs[ipSetIDXId].DportRange) {
					if err := DstPortRcTable(ctx, p4RtC, ipSetIDXId, dportRng, ipSetIDX.Protocol,
						Update); err != nil {
						log.Errorf("Failed to update entry in DstPortRcTable, err: %v", err)
						return err
					}
				}
			}
		}

		return nil

	case WorkloadAdd:
		workloadep := in.(store.PolicyWorkerEndPoint)
		for _, policyname := range workloadep.PolicyNameIngress {
			policy := store.PolicySet.PolicyMap[policyname]
			for ipsetidx, _ := range policy.IpSetIDXs {
				if err := AclPodIpProtoTable(ctx, p4RtC, policy.IpSetIDXs[ipsetidx].Protocol, workloadep.WorkerEp,
					ipsetidx, ipsetidx, "RX", Insert); err != nil {
					log.Errorf("Failed to add entry to AclPodIpProtoTable, err: %v", err)
					return err
				}
			}
		}

		for _, policyname := range workloadep.PolicyNameEgress {
			policy := store.PolicySet.PolicyMap[policyname]
			for ipsetidx, _ := range policy.IpSetIDXs {
				if err := AclPodIpProtoTable(ctx, p4RtC, policy.IpSetIDXs[ipsetidx].Protocol, workloadep.WorkerEp,
					ipsetidx, ipsetidx, "TX", Insert); err != nil {
					log.Errorf("Failed to add entry to AclPodIpProtoTable, err: %v", err)
					return err
				}
			}
		}
		return nil

	case WorkloadDel:
		workloadep := in.(store.PolicyWorkerEndPoint)
		for _, policyname := range workloadep.PolicyNameIngress {
			policy := store.PolicySet.PolicyMap[policyname]
			for ipsetidx, _ := range policy.IpSetIDXs {
				if err := AclPodIpProtoTable(ctx, p4RtC, policy.IpSetIDXs[ipsetidx].Protocol, workloadep.WorkerEp,
					ipsetidx, ipsetidx, "RX", Delete); err != nil {
					log.Errorf("Failed to delete entry from AclPodIpProtoTable, err: %v", err)
					return err
				}
			}
		}

		for _, policyname := range workloadep.PolicyNameEgress {
			policy := store.PolicySet.PolicyMap[policyname]
			for ipsetidx, _ := range policy.IpSetIDXs {
				if err := AclPodIpProtoTable(ctx, p4RtC, policy.IpSetIDXs[ipsetidx].Protocol, workloadep.WorkerEp,
					ipsetidx, ipsetidx, "TX", Delete); err != nil {
					log.Errorf("Failed to delete entry from AclPodIpProtoTable, err: %v", err)
					return err
				}
			}
		}
		return nil

	case WorkloadUpdate:
		workloadep := in.(store.PolicyWorkerEndPoint)
		workloadepold := store.PolicySet.WorkerEpMap[workloadep.WorkerEp]
		//ingress policy names
		//delete from policy tables for removed policies
		for _, policyname := range workloadepold.PolicyNameIngress {
			//if policyname from old store entry is not present in new entry, then delete
			if !IsNamePresent(policyname, workloadep.PolicyNameIngress) {
				policydel := store.PolicySet.PolicyMap[policyname]
				for ipsetidx, _ := range policydel.IpSetIDXs {
					if err := AclPodIpProtoTable(ctx, p4RtC, policydel.IpSetIDXs[ipsetidx].Protocol,
						workloadep.WorkerEp, 0, 0, "RX", Delete); err != nil {
						log.Errorf("Failed to delete entry from AclPodIpProtoTable, err: %v", err)
						return err
					}
				}
			}
		}
		//insert to policy tables the new policies
		for _, policyname := range workloadep.PolicyNameIngress {
			if !IsNamePresent(policyname, workloadepold.PolicyNameIngress) {
				policyadd := store.PolicySet.PolicyMap[policyname]
				for ipsetidx, _ := range policyadd.IpSetIDXs {
					if err := AclPodIpProtoTable(ctx, p4RtC, policyadd.IpSetIDXs[ipsetidx].Protocol,
						workloadep.WorkerEp, ipsetidx, ipsetidx, "RX", Insert); err != nil {
						log.Errorf("Failed to insert entry to AclPodIpProtoTable, err: %v", err)
						return err
					}
				}
			}
		}

		//egress policy names
		//delete from policy tables for removed policies
		for _, policyname := range workloadepold.PolicyNameEgress {
			//if policyname from old store entry is not present in new entry, then delete
			if !IsNamePresent(policyname, workloadep.PolicyNameEgress) {
				policydel := store.PolicySet.PolicyMap[policyname]
				for ipsetidx, _ := range policydel.IpSetIDXs {
					if err := AclPodIpProtoTable(ctx, p4RtC, policydel.IpSetIDXs[ipsetidx].Protocol, workloadep.WorkerEp,
						0, 0, "TX", Delete); err != nil {
						log.Errorf("Failed to delete entry from AclPodIpProtoTable, err: %v", err)
						return err
					}
				}
			}
		}
		//insert to policy tables the new policies
		for _, policyname := range workloadep.PolicyNameEgress {
			if !IsNamePresent(policyname, workloadepold.PolicyNameEgress) {
				policyadd := store.PolicySet.PolicyMap[policyname]
				for ipsetidx, _ := range policyadd.IpSetIDXs {
					if err := AclPodIpProtoTable(ctx, p4RtC, policyadd.IpSetIDXs[ipsetidx].Protocol, workloadep.WorkerEp,
						ipsetidx, ipsetidx, "TX", Insert); err != nil {
						log.Errorf("Failed to insert entry to AclPodIpProtoTable, err: %v", err)
						return err
					}
				}
			}
		}
		return nil
	default:
		return errors.New("Invalid operation type")
	}
}
