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
	"reflect"
	"os"

	log "github.com/sirupsen/logrus"
)

const (
	servicesFile = "/opt/inframanager/services_db.json"
)

func isServiceStoreEmpty() bool {
	if len(ServiceSet.ServiceMap) == 0 {
		return true
	} else {
		return false
	}
}

func InitServiceStore(setFwdPipe bool) bool {
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
        file, err := os.OpenFile(servicesFile, flags, 0600)
        if err != nil {
                log.Error("Failed to open", servicesFile)
                return false
        }
        file.Close()

        data, err := os.ReadFile(servicesFile)
        if err != nil {
                log.Error("Error reading ", servicesFile, err)
                return false
        }

        if len(data) == 0 {
                return true
        }

        err = json.Unmarshal(data, &ServiceSet.ServiceMap)
        if err != nil {
                log.Error("Error unmarshalling data from ", servicesFile, err)
                return false
        }

        return true
}

func (s Service) WriteToStore() bool {
	//aquire lock before adding entry into the map
	ServiceSet.ServiceLock.Lock()
	//append tmp entry to the map
	ServiceSet.ServiceMap[s.ClusterIp] = s
	//release lock after updating the map
	ServiceSet.ServiceLock.Unlock()
	return true
}

func (s Service) DeleteFromStore() bool {
	//aquire lock before adding entry into the map
	ServiceSet.ServiceLock.Lock()
	//delete tmp entry from the map
	delete(ServiceSet.ServiceMap, s.ClusterIp)
	//release lock after updating the map
	ServiceSet.ServiceLock.Unlock()
	return true
}

func (s Service) GetFromStore() store {

	res := ServiceSet.ServiceMap[s.ClusterIp]
	if reflect.DeepEqual(res, Service{}) {
		return nil
	} else {
		return res
	}
}

func (s Service) UpdateToStore() bool {
	fmt.Println("not implemented")
	return true
}

func RunSyncServiceInfo() bool {
	jsonStr, err := json.MarshalIndent(ServiceSet.ServiceMap, "", " ")
	if err != nil {
		log.Errorf("Failed to marshal service entries map %s", err)
		return false
	}

	if err = ioutil.WriteFile(servicesFile, jsonStr, 0600); err != nil {
		log.Errorf("Failed to write entries to %s, err %s",
			servicesFile, err)
		return false
	}
	return true
}
