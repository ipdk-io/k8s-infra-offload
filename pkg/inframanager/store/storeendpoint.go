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

package store

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	log "github.com/sirupsen/logrus"
)

const (
	storeFile = storePath + "cni_db.json"
)

func isEndPointStoreEmpty() bool {
	if len(EndPointSet.EndPointMap) == 0 {
		return true
	} else {
		return false
	}
}

func InitEndPointStore(setFwdPipe bool) bool {
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

	/* Create the store file if it doesn't exist */
	file, err := os.OpenFile(storeFile, flags, 0600)
	if err != nil {
		log.Error("Failed to open", storeFile)
		return false
	}
	file.Close()

	data, err := os.ReadFile(storeFile)
	if err != nil {
		log.Error("Error reading ", storeFile, err)
		return false
	}

	if len(data) == 0 {
		return true
	}

	err = json.Unmarshal(data, &EndPointSet.EndPointMap)
	if err != nil {
		log.Error("Error unmarshalling data from ", storeFile, err)
		return false
	}

	return true
}

func (ep EndPoint) WriteToStore() bool {
	//aquire lock before adding entry into the map
	EndPointSet.EndPointLock.Lock()
	//append tmp entry to the map
	EndPointSet.EndPointMap[ep.PodIpAddress] = ep
	//release lock after updating the map
	EndPointSet.EndPointLock.Unlock()

	return true
}

func (ep EndPoint) DeleteFromStore() bool {
	//aquire lock before adding entry into the map
	EndPointSet.EndPointLock.Lock()
	//delete tmp entry from the map
	delete(EndPointSet.EndPointMap, ep.PodIpAddress)
	//release lock after updating the map
	EndPointSet.EndPointLock.Unlock()
	return true
}

func (ep EndPoint) GetFromStore() store {
	res := EndPointSet.EndPointMap[ep.PodIpAddress]
	if (res == EndPoint{}) {
		return nil
	} else {
		return res
	}
}

func (ep EndPoint) UpdateToStore() bool {
	fmt.Println("not implemented")
	return true
}

func RunSyncEndPointInfo() bool {
	jsonStr, err := json.MarshalIndent(EndPointSet.EndPointMap, "", " ")
	if err != nil {
		log.Errorf("Failed to marshal endpoint entries map %s", err)
		return false
	}

	if err = ioutil.WriteFile(storeFile, jsonStr, 0600); err != nil {
		log.Errorf("Failed to write entries to %s, err %s",
			storeFile, err)
		return false
	}

	return true
}
