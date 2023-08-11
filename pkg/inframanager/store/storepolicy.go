package store

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"reflect"

	"github.com/ipdk-io/k8s-infra-offload/pkg/utils"
	log "github.com/sirupsen/logrus"
)

type retflag int

const (
	Fail retflag = iota
	Zerolength
	Datapresent
)

var (
	PolicyFile   = path.Join(StorePath, "policy_db.json")
	IpsetFile    = path.Join(StorePath, "ipset_db.json")
	WorkerepFile = path.Join(StorePath, "workerep_db.json")
)

func GetNewRuleGroupId() int {
	return PolicySet.RuleGroupIdStack.Pop()
}

func ReleaseRuleGroupId(val int) {
	PolicySet.RuleGroupIdStack.Push(val)
}

func IsPolicyStoreEmpty() bool {
	if len(PolicySet.PolicyMap) == 0 {
		return true
	} else {
		return false
	}
}

func IsIpsetStoreEmpty() bool {
	if len(PolicySet.IpSetMap) == 0 {
		return true
	} else {
		return false
	}
}

func IsWorkerepStoreEmpty() bool {
	if len(PolicySet.WorkerEpMap) == 0 {
		return true
	} else {
		return false
	}
}

func OpenPolicyStoreFiles(fileName string, flags int) (retflag, []byte) {
	verifiedFileName, err := utils.VerifiedFilePath(fileName, StorePath)
	if err != nil {
		log.Errorf("Failed to open %s", fileName)
		return Fail, nil
	}

	file, err := NewOpenFile(verifiedFileName, flags, 0755)
	if err != nil {
		log.Errorf("Failed to open %s", fileName)
		return Fail, nil
	}
	file.Close()

	data, err := NewReadFile(fileName)
	if err != nil {
		log.Errorf("Failed to  %s, err: %s", fileName, err)
		return Fail, nil
	}

	if len(data) == 0 {
		return Zerolength, nil
	}

	return Datapresent, data
}

func InitPolicyStore(setFwdPipe bool) bool {
	flags := os.O_CREATE

	/*
	   Initialize the store to empty while setting the
	   forwarding pipeline. It indicates that the p4-ovs
	   server has just started and pipeline is set.
	   And no stale forwarding rules should exist in the store.
	   Truncate if any entries from previous server runs.
	*/
	if setFwdPipe {
		flags = flags | os.O_TRUNC
	}

	if _, err := os.Stat(StorePath); errors.Is(err, os.ErrNotExist) {
		err := os.MkdirAll(StorePath, 0755)
		if err != nil {
			log.Errorf("Failed to create directory %s", StorePath)
			return false
		}
	}

	/* Create the store file if it doesn't exist */
	ret, data := OpenPolicyStoreFiles(PolicyFile, flags)
	if ret == Fail {
		return false
	} else if ret == Zerolength {
		return true
	} else {
		err := JsonUnmarshal(data, &PolicySet.PolicyMap)
		if err != nil {
			log.Errorf("Failed to unmarshal data from %s, err: %s", PolicyFile, err)
			return false
		}
	}

	ret, data = OpenPolicyStoreFiles(IpsetFile, flags)
	if ret == Fail {
		return false
	} else if ret == Zerolength {
		return true
	} else {
		err := JsonUnmarshal(data, &PolicySet.IpSetMap)
		if err != nil {
			log.Errorf("Failed to unmarshal data from %s, err: %s", IpsetFile, err)
			return false
		}
	}

	ret, data = OpenPolicyStoreFiles(WorkerepFile, flags)
	if ret == Fail {
		return false
	} else if ret == Zerolength {
		return true
	} else {
		err := JsonUnmarshal(data, &PolicySet.WorkerEpMap)
		if err != nil {
			log.Errorf("Failed to unmarshal data from %s, err: %s", WorkerepFile, err)
			return false
		}
		return true
	}

}

func (policy Policy) WriteToStore() bool {

	if reflect.DeepEqual(policy, Policy{}) {
		return false
	}

	for _, RuleGroup := range policy.RuleGroups {
		//Direction
		direction := RuleGroup.Direction
		if direction != "TX" && direction != "RX" {
			return false
		}

		for _, rule := range RuleGroup.Rules {
			//Cidr
			cidr := rule.Cidr
			ip, ipset, err := net.ParseCIDR(cidr)
			if err != nil {
				log.Errorf("Invalid Cidr = %s, ip=%s, ipset=%s", cidr, ip, ipset)
				return false
			}
			//PortRange
			portrange := rule.PortRange
			if len(portrange) > 2 {
				return false
			}
		}
	}

	PolicySet.PolicyLock.Lock()
	PolicySet.PolicyMap[policy.Name] = policy
	PolicySet.PolicyLock.Unlock()
	return true
}

func (ipsetadd IpSet) WriteToStore() bool {

	if reflect.DeepEqual(ipsetadd, IpSet{}) {
		return false
	}

	if ipsetadd.IpSetIDx < 0 || ipsetadd.IpSetIDx > 255 {
		return false
	}

	for _, ip := range ipsetadd.IpAddr {
		if net.ParseIP(ip) == nil {
			return false
		}
	}

	PolicySet.PolicyLock.Lock()
	PolicySet.IpSetMap[ipsetadd.IpsetID] = ipsetadd
	PolicySet.PolicyLock.Unlock()
	return true
}

func (ep PolicyWorkerEndPoint) WriteToStore() bool {

	if reflect.DeepEqual(ep, PolicyWorkerEndPoint{}) {
		return false
	}
	PolicySet.PolicyLock.Lock()
	PolicySet.WorkerEpMap[ep.WorkerEp] = ep
	PolicySet.PolicyLock.Unlock()
	return true
}

func remove(s []string, r string) ([]string, bool) {
	ret := false
	for i, v := range s {
		if v == r {
			ret = true
			return append(s[:i], s[i+1:]...), ret
		}
		ret = false
	}
	return s, ret
}

func (policy Policy) DeleteFromStore() bool {

	if pEntry := policy.GetFromStore(); pEntry == nil {
		return false
	}

	//delete the corresponding ipsetid from ipset map
	var f bool
	for _, RuleGroup := range policy.RuleGroups {
		for _, rule := range RuleGroup.Rules {
			ipsetid := rule.IpSetID
			if ipsetid != "" {
				PolicySet.PolicyLock.Lock()
				delete(PolicySet.IpSetMap, ipsetid)
				PolicySet.PolicyLock.Unlock()
			}
		}
	}
	PolicySet.PolicyLock.Lock()
	delete(PolicySet.PolicyMap, policy.Name)
	PolicySet.PolicyLock.Unlock()

	//delete corresponding policy name from worker ep map as well
	for ep, val := range PolicySet.WorkerEpMap {
		val.PolicyNameIngress, f = remove(val.PolicyNameIngress, policy.Name)
		if f {
			PolicySet.WorkerEpMap[ep] = val
		}
		val.PolicyNameEgress, f = remove(val.PolicyNameEgress, policy.Name)
		if f {
			PolicySet.WorkerEpMap[ep] = val
		}
	}

	return true
}

func (ipsetdel IpSet) DeleteFromStore() bool {

	ipsetEntry := PolicySet.IpSetMap[ipsetdel.IpsetID]
	if reflect.DeepEqual(ipsetEntry, IpSet{}) {
		return false
	}

	ipsetidx := ipsetdel.IpSetIDx
	ruleid := ipsetdel.RuleID

	res := PolicySet.PolicyMap[ipsetdel.PolicyName]
	if reflect.DeepEqual(res, Policy{}) {
		return false
	} else {
		PolicySet.PolicyLock.Lock()
		if p, ok1 := res.RuleGroups[ipsetidx]; ok1 {
			if r, ok2 := p.Rules[ruleid]; ok2 {
				r.IpSetID = ""
				p.Rules[ruleid] = r
			}
			res.RuleGroups[ipsetidx] = p
		}
		PolicySet.PolicyLock.Unlock()
	}

	PolicySet.PolicyLock.Lock()
	delete(PolicySet.IpSetMap, ipsetdel.IpsetID)
	PolicySet.PolicyLock.Unlock()

	return true
}

func (workerepdel PolicyWorkerEndPoint) DeleteFromStore() bool {

	workerepEntry := PolicySet.WorkerEpMap[workerepdel.WorkerEp]
	if reflect.DeepEqual(workerepEntry, PolicyWorkerEndPoint{}) {
		return false
	}

	PolicySet.PolicyLock.Lock()
	delete(PolicySet.WorkerEpMap, workerepdel.WorkerEp)
	PolicySet.PolicyLock.Unlock()
	return true
}

func GetPolicy(pName string) store {
	res := PolicySet.PolicyMap[pName]

	if reflect.DeepEqual(res, Policy{}) {
		return nil
	} else {
		return res
	}

}

func GetWorkerEp(epName string) store {
	res := PolicySet.WorkerEpMap[epName]
	if reflect.DeepEqual(res, PolicyWorkerEndPoint{}) {
		return nil
	} else {
		return res
	}
}

func (policy Policy) GetFromStore() store {
	res := PolicySet.PolicyMap[policy.Name]

	if reflect.DeepEqual(res, Policy{}) {
		return nil
	} else {
		return res
	}
}

func (policy Policy) DeleteWorkerEp(workerEp string) bool {
	pEntry := policy.GetFromStore()

	if pEntry == nil {
		return false
	}
	p := pEntry.(Policy)

	if utils.IsIn(workerEp, p.WorkerEps) {
		p.WorkerEps = utils.RemoveStr(workerEp, p.WorkerEps)
		PolicySet.PolicyLock.Lock()
		PolicySet.PolicyMap[policy.Name] = p
		PolicySet.PolicyLock.Unlock()
		return true
	}

	return false
}

func (policy Policy) AddWorkerEp(workerEp string) bool {
	pEntry := policy.GetFromStore()

	if pEntry == nil {
		return false
	}
	p := pEntry.(Policy)

	if !utils.IsIn(workerEp, p.WorkerEps) {
		p.WorkerEps = append(p.WorkerEps, workerEp)
		PolicySet.PolicyLock.Lock()
		PolicySet.PolicyMap[policy.Name] = p
		PolicySet.PolicyLock.Unlock()
		return true
	}

	return false
}

func (ipsetget IpSet) GetFromStore() store {
	res := PolicySet.IpSetMap[ipsetget.IpsetID]
	if reflect.DeepEqual(res, IpSet{}) {
		return nil
	} else {
		return res
	}
}

func (workerepget PolicyWorkerEndPoint) GetFromStore() store {
	res := PolicySet.WorkerEpMap[workerepget.WorkerEp]
	if reflect.DeepEqual(res, PolicyWorkerEndPoint{}) {
		return nil
	} else {
		return res
	}
}

// update to store for policy struct, should invoke delete first and then invoke
// write call, modify later
func (policy Policy) UpdateToStore() bool {
	/*
		Check if entry exists
	*/
	if entry := policy.GetFromStore(); entry != nil {
		storePolicy := entry.(Policy)

		/*
			store has the same data. No need to update.
		*/
		if reflect.DeepEqual(policy, storePolicy) {
			return true
		}

		// Delete not required as WriteToStore overwrites the same entry
		//If ret := policy.DeleteFromStore(); !ret {
		//	return false
		//}
	}

	return policy.WriteToStore()
}

func (ipsetmod IpSet) UpdateToStore() bool {
	ipsetEntry := PolicySet.IpSetMap[ipsetmod.IpsetID]
	if reflect.DeepEqual(ipsetEntry, IpSet{}) {
		return false
	}
	if reflect.DeepEqual(ipsetEntry, ipsetmod) {
		return false
	}

	ipsetEntry.IpAddr = ipsetmod.IpAddr
	return ipsetEntry.WriteToStore()
}

func (ep PolicyWorkerEndPoint) UpdateToStore() bool {
	/*
		Check if entry exists
	*/
	if entry := ep.GetFromStore(); entry != nil {
		storeEp := entry.(PolicyWorkerEndPoint)

		/*
			store has the same data. No need to update.
		*/
		if reflect.DeepEqual(ep, storeEp) {
			return true
		}

		// Delete not required as WriteToStore overwrites the same entry
		//If ret := ep.DeleteFromStore(); !ret {
		//	return false
		//}
	}

	return ep.WriteToStore()
}

func RunSyncPolicyInfo() bool {
	jsonStr, err := JsonMarshalIndent(PolicySet.PolicyMap, "", " ")
	if err != nil {
		fmt.Println(err)
		return false
	}

	if err = NewWriteFile(PolicyFile, jsonStr, 0755); err != nil {
		log.Errorf("Failed to write entries, err: %s", err)
		return false
	}

	return true
}

func RunSyncIpSetInfo() bool {
	jsonStr, err := JsonMarshalIndent(PolicySet.IpSetMap, "", " ")
	if err != nil {
		fmt.Println(err)
		return false
	}

	if err = NewWriteFile(IpsetFile, jsonStr, 0755); err != nil {
		log.Errorf("Failed to write entries, err: %s", err)
		return false
	}

	return true
}

func RunSyncWorkerEpInfo() bool {
	jsonStr, err := JsonMarshalIndent(PolicySet.WorkerEpMap, "", " ")
	if err != nil {
		fmt.Println(err)
		return false
	}

	if err = NewWriteFile(WorkerepFile, jsonStr, 0755); err != nil {
		log.Errorf("Failed to write entries, err: %s", err)
		return false
	}

	return true
}
