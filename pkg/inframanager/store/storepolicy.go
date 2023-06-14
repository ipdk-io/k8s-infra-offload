package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"

	log "github.com/sirupsen/logrus"
)

type retflag int

const (
	Fail retflag = iota
	Zerolength
	Datapresent
)

const (
	PolicyFile   = storePath + "policy_db.json"
	IpsetFile    = storePath + "ipset_db.json"
	WorkerepFile = storePath + "workerep_db.json"
)

func GetNewPolicyIpsetIDX() int {
	return PolicySet.IpsetidxStack.Pop()
}

func ReleasePolicyIpsetIDX(val int) {
	PolicySet.IpsetidxStack.Push(val)
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
	file, err := NewOpenFile(fileName, flags, 0600)
	if err != nil {
		log.Error("Failed to open", fileName)
		return Fail, nil
	}
	file.Close()

	data, err := NewReadFile(fileName)
	if err != nil {
		log.Error("Error reading ", fileName, err)
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

	if _, err := os.Stat(storePath); errors.Is(err, os.ErrNotExist) {
		err := os.MkdirAll(storePath, 0640)
		if err != nil {
			log.Error("Failed to create directory ", storePath)
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
			log.Error("Error unmarshalling data from ", PolicyFile, err)
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
			log.Error("Error unmarshalling data from ", IpsetFile, err)
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
			log.Error("Error unmarshalling data from ", WorkerepFile, err)
			return false
		}
		return true
	}

}

func (policyadd Policy) WriteToStore() bool {
	PolicySet.PolicyLock.Lock()
	PolicySet.PolicyMap[policyadd.PolicyName] = policyadd
	PolicySet.PolicyLock.Unlock()
	return true
}

func (ipsetadd IpSet) WriteToStore() bool {
	PolicySet.PolicyLock.Lock()
	PolicySet.IpSetMap[ipsetadd.IpsetID] = ipsetadd
	PolicySet.PolicyLock.Unlock()
	return true
}

func (workerepadd PolicyWorkerEndPoint) WriteToStore() bool {
	PolicySet.PolicyLock.Lock()
	PolicySet.WorkerEpMap[workerepadd.WorkerEp] = workerepadd
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

func (policydel Policy) DeleteFromStore() bool {
	//delete the corresponding ipsetid from ipset map
	var f bool
	for ipsetidx, _ := range policydel.IpSetIDXs {
		for ruleid, _ := range policydel.IpSetIDXs[ipsetidx].Rules {
			ipsetid := policydel.IpSetIDXs[ipsetidx].Rules[ruleid].IpSetID
			if ipsetid != "" {
				PolicySet.PolicyLock.Lock()
				delete(PolicySet.IpSetMap, ipsetid)
				PolicySet.PolicyLock.Unlock()
			}
		}
	}
	PolicySet.PolicyLock.Lock()
	delete(PolicySet.PolicyMap, policydel.PolicyName)
	PolicySet.PolicyLock.Unlock()

	//delete corresponding policy name from worker ep map as well
	for ep, val := range PolicySet.WorkerEpMap {
		val.PolicyNameIngress, f = remove(val.PolicyNameIngress, policydel.PolicyName)
		if f {
			PolicySet.WorkerEpMap[ep] = val
		}
		val.PolicyNameEgress, f = remove(val.PolicyNameEgress, policydel.PolicyName)
		if f {
			PolicySet.WorkerEpMap[ep] = val
		}
	}

	return true
}

func (ipsetdel IpSet) DeleteFromStore() bool {
	ipsetidx := ipsetdel.IpSetIDx
	ruleid := ipsetdel.RuleID

	res := PolicySet.PolicyMap[ipsetdel.PolicyName]
	if reflect.DeepEqual(res, Policy{}) {
		return false
	} else {
		PolicySet.PolicyLock.Lock()
		if p, ok1 := res.IpSetIDXs[ipsetidx]; ok1 {
			if r, ok2 := p.Rules[ruleid]; ok2 {
				r.IpSetID = ""
				p.Rules[ruleid] = r
			}
			res.IpSetIDXs[ipsetidx] = p
		}
		PolicySet.PolicyLock.Unlock()
	}

	PolicySet.PolicyLock.Lock()
	delete(PolicySet.IpSetMap, ipsetdel.IpsetID)
	PolicySet.PolicyLock.Unlock()

	return true
}

func (workerepdel PolicyWorkerEndPoint) DeleteFromStore() bool {
	PolicySet.PolicyLock.Lock()
	delete(PolicySet.WorkerEpMap, workerepdel.WorkerEp)
	PolicySet.PolicyLock.Unlock()
	return true
}

func (policyget Policy) GetFromStore() store {
	res := PolicySet.PolicyMap[policyget.PolicyName]

	if reflect.DeepEqual(res, Policy{}) {
		return nil
	} else {
		return res
	}
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
func (policymod Policy) UpdateToStore() bool {
	policyEntry := PolicySet.PolicyMap[policymod.PolicyName]
	if reflect.DeepEqual(policyEntry, Policy{}) {
		//		return false
		return policymod.WriteToStore()
	}

	ret := policyEntry.DeleteFromStore()
	if !ret {
		return false
	}

	return policymod.WriteToStore()
}

func (ipsetmod IpSet) UpdateToStore() bool {
	ipsetEntry := PolicySet.IpSetMap[ipsetmod.IpsetID]
	if reflect.DeepEqual(ipsetEntry, IpSet{}) {
		return false
	}

	ipsetEntry.IpAddr = nil
	ipsetEntry.IpAddr = ipsetmod.IpAddr
	return ipsetEntry.WriteToStore()
}

func (workerepmod PolicyWorkerEndPoint) UpdateToStore() bool {
	workerepEntry := PolicySet.WorkerEpMap[workerepmod.WorkerEp]
	if reflect.DeepEqual(workerepEntry, PolicyWorkerEndPoint{}) {
		return false
	}

	workerepEntry.PolicyNameIngress = workerepmod.PolicyNameIngress
	workerepEntry.PolicyNameEgress = workerepmod.PolicyNameEgress
	return workerepEntry.WriteToStore()
}

func RunSyncPolicyInfo() bool {
	jsonStr, err := json.MarshalIndent(PolicySet.PolicyMap, "", " ")
	if err != nil {
		fmt.Println(err)
		return false
	}

	_ = ioutil.WriteFile(PolicyFile, jsonStr, 0777)

	return true
}

func RunSyncIpSetInfo() bool {
	jsonStr, err := json.MarshalIndent(PolicySet.IpSetMap, "", " ")
	if err != nil {
		fmt.Println(err)
		return false
	}

	_ = ioutil.WriteFile(IpsetFile, jsonStr, 0777)

	return true
}

func RunSyncWorkerEpInfo() bool {
	jsonStr, err := json.MarshalIndent(PolicySet.WorkerEpMap, "", " ")
	if err != nil {
		fmt.Println(err)
		return false
	}

	_ = ioutil.WriteFile(WorkerepFile, jsonStr, 0777)

	return true
}
