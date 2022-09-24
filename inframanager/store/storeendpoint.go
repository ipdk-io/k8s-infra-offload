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
)

func isEndPointStoreEmpty() bool {
	if len(EndPointSet.EndPointMap) == 0 {
		return true
	} else {
		return false
	}
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

func (ep EndPoint) GetFromStore() (store, error) {
	if isEndPointStoreEmpty() {
		return nil, nil
	}

	res := EndPointSet.EndPointMap[ep.PodIpAddress]
	if (res == EndPoint{}) {
		err := fmt.Errorf("no match found for key %s", ep.PodIpAddress)
		return nil, err
	} else {
		return res, nil
	}
}

func (ep EndPoint) UpdateToStore() bool {
	fmt.Println("not implemented")
	return true
}

func RunSyncEndPointInfo() bool {
	jsonStr, err := json.MarshalIndent(EndPointSet.EndPointMap, "", " ")
	if err != nil {
		fmt.Println(err)
		return false
	}

	_ = ioutil.WriteFile("cni_add.json", jsonStr, 0777)

	return true
}
