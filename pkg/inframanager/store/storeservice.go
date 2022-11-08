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

	log "github.com/sirupsen/logrus"
)

const (
	servicesFile = "/opt/inframanager/services_db.json"
)

func isServiceStoreEmpty() bool {
	if len(ServiceMap.ServiceMap) == 0 {
		return true
	} else {
		return false
	}
}

func (s Service) WriteToStore() bool {
	//aquire lock before adding entry into the map
	ServiceMap.ServiceLock.Lock()
	//append tmp entry to the map
	ServiceMap.ServiceMap[s.ClusterIp] = s
	//release lock after updating the map
	ServiceMap.ServiceLock.Unlock()
	return true
}

func (s Service) DeleteFromStore() bool {
	//aquire lock before adding entry into the map
	ServiceMap.ServiceLock.Lock()
	//delete tmp entry from the map
	delete(ServiceMap.ServiceMap, s.ClusterIp)
	//release lock after updating the map
	ServiceMap.ServiceLock.Unlock()
	return true
}

func (s Service) GetFromStore() store {

	res := ServiceMap.ServiceMap[s.ClusterIp]
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
	jsonStr, err := json.MarshalIndent(ServiceMap.ServiceMap, "", " ")
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
