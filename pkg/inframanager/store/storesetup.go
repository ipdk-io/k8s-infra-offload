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
	"net"
	"os"
	"path"
	"sync"

	"github.com/ipdk-io/k8s-infra-offload/pkg/utils"
	log "github.com/sirupsen/logrus"
)

var (
	StoreSetupFile = path.Join(StorePath, "setup_db.json")
)

var setupMutex = &sync.Mutex{}

func InitSetupStore(setFwdPipe bool) bool {

	onceSetup.Do(func() {
		Setup = &SetupData{}
	})

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
		err := os.MkdirAll(StorePath, 0700)
		if err != nil {
			log.Errorf("Failed to create directory %s, err: %s", StorePath, err)
			return false
		}
	}

	verifiedFileName, err := utils.VerifiedFilePath(StoreSetupFile, StorePath)
	if err != nil {
		log.Errorf("Failed to open %s, error: %s ", StoreSetupFile, err)
		return false
	}

	/* Create the store file if it doesn't exist */
	file, err := NewOpenFile(verifiedFileName, flags, 0700)
	log.Info("store ep file path:", StoreSetupFile)
	if err != nil {
		log.Errorf("Failed to open %s, error: %s", StoreSetupFile, err)
		return false
	}
	err = file.Close()
	if err != nil {
		log.Errorf("Failed to close file %s, error: %s",
			StoreSetupFile, err)
		return false
	}
	data, err := NewReadFile(StoreSetupFile)
	if err != nil {
		log.Errorf("Failed to read %s, error: %s", StoreSetupFile, err)
		return false
	}

	if len(data) == 0 {
		return true
	}

	err = JsonUnmarshal(data, &Setup)
	if err != nil {
		log.Errorf("Failed to unmarshal data from %s, error: %s", StoreSetupFile, err)
		return false
	}

	return true
}

func GetHostInterface() Iface {
	return Setup.HostInterface
}

func SetHostInterface(ifName string, ip string, mac string) bool {

	if len(ifName) == 0 {
		log.Errorf("Invalid interface name %s", ifName)
		return false
	}

	if len(mac) == 0 {
		log.Errorf("Invalid mac address %s", mac)
		return false
	}
	if _, err := net.ParseMAC(mac); err != nil {
		log.Errorf("Invalid mac address %s", mac)
		return false
	}

	if len(ip) == 0 {
		log.Errorf("Invalid mac address %s", mac)
		return false
	}
	if net.ParseIP(ip) == nil {
		log.Errorf("Invalid ip address %s", ip)
		return false
	}

	setupMutex.Lock()
	Setup.HostInterface.IfName = ifName
	Setup.HostInterface.Ip = ip
	Setup.HostInterface.Mac = mac
	setupMutex.Unlock()

	return true
}

func SetDefaultRule() {
	setupMutex.Lock()
	Setup.SetDefaultRule = true
	setupMutex.Unlock()
}

func ClearDefaultRule() {
	setupMutex.Lock()
	Setup.SetDefaultRule = false
	setupMutex.Unlock()
}

func IsDefaultRuleSet() bool {
	return Setup.SetDefaultRule
}

func RunSyncSetupInfo() bool {
	jsonStr, err := JsonMarshalIndent(Setup, "", " ")
	if err != nil {
		log.Errorf("Failed to marshal endpoint entries map %s", err)
		return false
	}

	if err = NewWriteFile(StoreSetupFile, jsonStr, 0700); err != nil {
		log.Errorf("Failed to write entries to %s, err %s",
			StoreSetupFile, err)
		return false
	}

	return true
}
