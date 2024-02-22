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
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/ipdk-io/k8s-infra-offload/pkg/utils"
	log "github.com/sirupsen/logrus"
)

var (
	StoreEpFile = path.Join(StorePath, "cni_db.json")
	epFileMutex = &sync.Mutex{}
	epBufDirty  = false
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

	if _, err := os.Stat(StorePath); errors.Is(err, os.ErrNotExist) {
		err := os.MkdirAll(StorePath, 0755)
		if err != nil {
			log.Errorf("Failed to create directory %s, err: %s", StorePath, err)
			return false
		}
	}

	verifiedFileName, err := utils.VerifiedFilePath(StoreEpFile, StorePath)
	if err != nil {
		log.Errorf("Failed to open %s, error: %s ", StoreEpFile, err)
		return false
	}

	/* Create the store file if it doesn't exist */
	file, err := NewOpenFile(verifiedFileName, flags, 0755)
	log.Info("store ep file path:", StoreEpFile)
	if err != nil {
		log.Errorf("Failed to open %s, error: %s", StoreEpFile, err)
		return false
	}
	file.Close()

	data, err := NewReadFile(StoreEpFile)
	if err != nil {
		log.Errorf("Failed to read %s, error: %s", StoreEpFile, err)
		return false
	}

	if len(data) == 0 {
		return true
	}

	err = JsonUnmarshal(data, &EndPointSet.EndPointMap)
	if err != nil {
		log.Errorf("Failed to unmarshal data from %s, error: %s", StoreEpFile, err)
		return false
	}

	return true
}

func (ep EndPoint) WriteToStore() bool {
	if strings.TrimSpace(ep.PodIpAddress) == "" || len(ep.PodIpAddress) == 0 {
		log.Errorf("Empty IP address srting")
		return false
	}

	if net.ParseIP(ep.PodIpAddress) == nil {
		log.Errorf("Invalid IP Address %s", ep.PodIpAddress)
		return false
	}

	_, err := net.ParseMAC(ep.PodMacAddress)
	if err != nil {
		log.Errorf("Invalid MAC Address %s", ep.PodMacAddress)
		return false
	}
	EndPointSet.EndPointLock.Lock()
	defer EndPointSet.EndPointLock.Unlock()
	EndPointSet.EndPointMap[ep.PodIpAddress] = ep
	epBufDirty = true

	return true
}

func (ep EndPoint) DeleteFromStore() bool {
	if strings.TrimSpace(ep.PodIpAddress) == "" || len(ep.PodIpAddress) == 0 {
		log.Errorf("Empty IP address srting")
		return false
	}

	if net.ParseIP(ep.PodIpAddress) == nil {
		log.Errorf("Invalid IP Address %s", ep.PodIpAddress)
		return false
	}

	EndPointSet.EndPointLock.Lock()
	defer EndPointSet.EndPointLock.Unlock()
	delete(EndPointSet.EndPointMap, ep.PodIpAddress)
	epBufDirty = true
	return true
}

func (ep EndPoint) GetFromStore() store {
	if strings.TrimSpace(ep.PodIpAddress) == "" || len(ep.PodIpAddress) == 0 {
		log.Errorf("Empty IP address srting")
		return nil
	}

	if net.ParseIP(ep.PodIpAddress) == nil {
		log.Errorf("Invalid IP Address %s", ep.PodIpAddress)
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
	EndPointSet.EndPointLock.Lock()
	defer EndPointSet.EndPointLock.Unlock()
	epBufDirty = true
	return true
}

func RunSyncEndPointInfo() bool {

	/*
		Flush the entries to the file only when there is an update
	*/
	EndPointSet.EndPointLock.Lock()
	if !epBufDirty {
		EndPointSet.EndPointLock.Unlock()
		return true
	}
	EndPointSet.EndPointLock.Unlock()

	epFileMutex.Lock()
	jsonStr, err := JsonMarshalIndent(EndPointSet.EndPointMap, "", " ")
	if err != nil {
		log.Errorf("Failed to marshal endpoint entries map %s", err)
		epFileMutex.Unlock()
		return false
	}

	if err = NewWriteFile(StoreEpFile, jsonStr, 0755); err != nil {
		log.Errorf("Failed to write entries to %s, err %s",
			StoreEpFile, err)
		epFileMutex.Unlock()
		return false
	}
	epFileMutex.Unlock()

	EndPointSet.EndPointLock.Lock()
	defer EndPointSet.EndPointLock.Unlock()
	epBufDirty = false

	return true
}
