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
	"github.com/ipdk-io/k8s-infra-offload/pkg/utils"
	//p4_v1 "github.com/p4lang/p4runtime/go/p4/v1"
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

func UpdatePolicyDefaultEntries(ctx context.Context, p4RtC *client.Client, checkAclResultEntries [][]byte, action InterfaceType) error {
	return nil

}

func AclPodIpProtoTable(ctx context.Context, p4RtC *client.Client,
	protocol uint8, workerep string, polID uint16, rangeID uint16, direction string,
	action InterfaceType) error {
	var tableName, matchAction, addrKey string
	var pLen int32
	var params [][]byte

	switch direction {
	case "RX":
		tableName = "k8s_dp_control.acl_pod_ip_proto_table_ingress"
		addrKey = "hdr.ipv4.dst_addr"
	case "TX":
		tableName = "k8s_dp_control.acl_pod_ip_proto_table_egress"
		addrKey = "hdr.ipv4.src_addr"
	default:
		log.Errorf("Invalid direction %v", action)
		return fmt.Errorf("Invalid direction")
	}

	if protocol != 0 {
		pLen = 8
		matchAction = "k8s_dp_control.set_range_check_ref"
		params = [][]byte{ToBytes(polID),
			ToBytes(rangeID)}
	} else {
		pLen = 1
		matchAction = "k8s_dp_control.set_status_match_ipset_only"
		params = [][]byte{ToBytes(polID)}
	}

	entry := p4RtC.NewTableEntry(
		tableName,
		map[string]client.MatchInterface{
			addrKey: &client.ExactMatch{
				Value: Pack32BinaryIP4(workerep),
			},
			"hdr.ipv4.protocol": &client.LpmMatch{
				Value: ToBytes(protocol),
				PLen:  pLen,
			},
		},
		p4RtC.NewTableActionDirect(matchAction, params),
		nil,
	)

	switch action {
	case Insert:
		if err := p4RtC.InsertTableEntry(ctx, entry); err != nil {
			log.Errorf("Cannot insert entry into %s: %v", tableName, err)
			return err
		}

	case Delete:
		entry.Action = nil
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

func AclIpSetMatchTable(ctx context.Context, p4RtC *client.Client,
	polID uint16, cidr string, mask uint8, direction string, action InterfaceType) error {
	var tableName, addrKey string

	switch direction {
	case "TX":
		tableName = "k8s_dp_control.acl_ipset_match_table_egress"
		addrKey = "hdr.ipv4.dst_addr"
	case "RX":
		tableName = "k8s_dp_control.acl_ipset_match_table_ingress"
		addrKey = "hdr.ipv4.src_addr"
	default:
		log.Errorf("Invalid direction %v", action)
		return fmt.Errorf("Invalid direction")
	}

	res := strings.Split(cidr, "/")
	ip := res[0]
	plen, err := strconv.Atoi(res[1])
	if err != nil {
		log.Errorf("Invalid cidr %s: err: %v", cidr, err)
		return err
	}

	entry := p4RtC.NewTableEntry(
		tableName,
		map[string]client.MatchInterface{
			"meta.acl_pol_id": &client.ExactMatch{
				Value: ToBytes(polID),
			},
			addrKey: &client.LpmMatch{
				Value: Pack32BinaryIP4(ip),
				PLen:  int32(plen),
			},
		},
		p4RtC.NewTableActionDirect("k8s_dp_control.set_ipset_match_result",
			[][]byte{ToBytes(mask)}),
		nil,
	)

	switch action {
	case Insert:
		if err := p4RtC.InsertTableEntry(ctx, entry); err != nil {
			log.Errorf("Cannot insert entry into %s: %v", tableName, err)
			return err
		}

	case Delete:
		entry.Action = nil
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

func DstPortRcTable(ctx context.Context, p4RtC *client.Client,
	polID uint16, portrange []uint16, protocol uint8,
	action InterfaceType) error {
	var tableName, matchAction string
	var ports = [][]byte{}

	for i := range portrange {
		ports = append(ports, ToBytes(portrange[i]))
	}

	switch protocol {
	case PROTO_TCP:
		tableName = "k8s_dp_control.tcp_dport_rc_table"
		matchAction = "k8s_dp_control.do_range_check_tcp"

	case PROTO_UDP:
		tableName = "k8s_dp_control.udp_dport_rc_table"
		matchAction = "k8s_dp_control.do_range_check_udp"
	}

	entry := p4RtC.NewTableEntry(
		tableName,
		map[string]client.MatchInterface{
			"meta.acl_pol_id": &client.ExactMatch{
				Value: ToBytes(polID),
			},
		},
		p4RtC.NewTableActionDirect(matchAction, ports),
		nil,
	)

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
		entry.Action = nil
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
	for id, ruleGroup := range ruleGroups {
		if ruleGroup.Direction == direction {
			if err := AclPodIpProtoTable(ctx, p4RtC, ruleGroup.Protocol, ip,
				id, id, ruleGroup.Direction, action); err != nil {
				log.Errorf("Failed to %s entry from AclPodIpProtoTable, err: %v", GetStr(action), err)
				return err
			}
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
