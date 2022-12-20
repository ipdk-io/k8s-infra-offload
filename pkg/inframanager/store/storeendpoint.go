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
	"fmt"
	"net"
	"os"

	log "github.com/sirupsen/logrus"
)

const (
	StoreEpFile = storePath + "cni_db.json"
)

func IsEndPointStoreEmpty() bool {
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
	file, err := NewOpenFile(StoreEpFile, flags, 0600)
	if err != nil {
		log.Error("Failed to open", StoreEpFile)
		return false
	}
	file.Close()

	data, err := NewReadFile(StoreEpFile)
	if err != nil {
		log.Error("Error reading ", StoreEpFile, err)
		return false
	}

	if len(data) == 0 {
		return true
	}

	err = JsonUnmarshal(data, &EndPointSet.EndPointMap)
	if err != nil {
		log.Error("Error unmarshalling data from ", StoreEpFile, err)
		return false
	}

	return true
}

func (ep EndPoint) WriteToStore() bool {
	if net.ParseIP(ep.PodIpAddress) == nil {
		log.Errorf("Invalid IP Address %s", ep.PodIpAddress)
		return false
	}

	_, err := net.ParseMAC(ep.PodMacAddress)
	if err != nil {
		log.Errorf("Invalid MAC Address %s", ep.PodMacAddress)
		return false
	}
	//aquire lock before adding entry into the map
	EndPointSet.EndPointLock.Lock()
	//append ep entry to the map
	EndPointSet.EndPointMap[ep.PodIpAddress] = ep
	//release lock after updating the map
	EndPointSet.EndPointLock.Unlock()

	return true
}

func (ep EndPoint) DeleteFromStore() bool {
	if net.ParseIP(ep.PodIpAddress) == nil {
		log.Errorf("Invalid IP Address %s", ep.PodIpAddress)
		return false
	}

	_, err := net.ParseMAC(ep.PodMacAddress)
	if err != nil {
		log.Errorf("Invalid MAC Address %s", ep.PodMacAddress)
		return false
	}

	//aquire lock before adding entry into the map
	EndPointSet.EndPointLock.Lock()
	//delete tmp entry from the map
	delete(EndPointSet.EndPointMap, ep.PodIpAddress)
	//release lock after updating the map
	EndPointSet.EndPointLock.Unlock()
	return true
}

func (ep EndPoint) GetFromStore() store {
	if net.ParseIP(ep.PodIpAddress) == nil {
		log.Errorf("Invalid IP Address %s", ep.PodIpAddress)
		return nil
	}

	_, err := net.ParseMAC(ep.PodMacAddress)
	if err != nil {
		log.Errorf("Invalid MAC Address %s", ep.PodMacAddress)
		return nil
	}

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
	jsonStr, err := JsonMarshalIndent(EndPointSet.EndPointMap, "", " ")
	if err != nil {
		log.Errorf("Failed to marshal endpoint entries map %s", err)
		return false
	}

	if err = NewWriteFile(StoreEpFile, jsonStr, 0600); err != nil {
		log.Errorf("Failed to write entries to %s, err %s",
			StoreEpFile, err)
		return false
	}

	return true
}
