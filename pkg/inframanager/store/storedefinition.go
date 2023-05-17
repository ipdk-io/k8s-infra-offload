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
	"io/ioutil"
	"os"
	"sync"
)

const (
	storePath = "/var/lib/cni/inframanager/"
)

type store interface {
	WriteToStore() bool
	DeleteFromStore() bool
	GetFromStore() store
	UpdateToStore() bool
}

type EndPoint struct {
	PodIpAddress  string
	InterfaceID   uint32
	PodMacAddress string
}

type EndPointCollection struct {
	EndPointMap  map[string]EndPoint
	EndPointLock *sync.Mutex
}

type Service struct {
	ClusterIp       string
	MacAddr         string
	Proto           string
	Port            uint32
	GroupID         uint32
	ServiceEndPoint map[string]ServiceEndPoint
	NumEndPoints    uint32
}

type ServiceEndPoint struct {
	IpAddress      string
	Port           uint32
	MemberID       uint32
	ModBlobPtrDNAT uint32
}

type ServiceCollection struct {
	ServiceMap  map[string]Service
	ServiceLock *sync.Mutex
}

type Policy struct {
	PolicyName string
	IpSetIDx   map[uint16]IpSetIDX
}

type IpSetIDX struct {
	IpSetIDx   uint16
	Direction  string
	Protocol   uint8
	RuleID     map[string]Rule
	DportRange []uint16
}

type Rule struct {
	RuleID    string
	PortRange []uint16
	RuleMask  uint8 //hex
	Cidr      string
	IpSetID   string
}

type IpSet struct {
	IpsetID    string
	IpSetIDx   uint16
	PolicyName string
	RuleID     string
	IpAddr     []string
}

type PolicyWorkerEndPoint struct {
	WorkerEp          string
	PolicyNameIngress []string
	PolicyNameEgress  []string
}

type PolicyCollection struct {
	PolicyMap   map[string]Policy
	IpSetMap    map[string]IpSet
	WorkerEpMap map[string]PolicyWorkerEndPoint
	PolicyLock  *sync.Mutex
}

var ServiceSet *ServiceCollection
var EndPointSet *EndPointCollection
var PolicySet *PolicyCollection

var once sync.Once
var onceService sync.Once
var oncePolicy sync.Once

var (
	JsonMarshalIndent = json.MarshalIndent
	NewOpenFile       = os.OpenFile
	NewReadFile       = os.ReadFile
	NewWriteFile      = ioutil.WriteFile
	JsonUnmarshal     = json.Unmarshal
)

func NewEndPoint() {
	once.Do(func() {
		EndPointSet = &EndPointCollection{EndPointMap: make(map[string]EndPoint),
			EndPointLock: &sync.Mutex{}} //call this from core manager before setting pipeline
	})
}

func NewService() {
	onceService.Do(func() {
		ServiceSet = &ServiceCollection{ServiceMap: make(map[string]Service),
			ServiceLock: &sync.Mutex{}}
	})
}

func NewPolicy() {
	oncePolicy.Do(func() {
		PolicySet = &PolicyCollection{PolicyMap: make(map[string]Policy),
			IpSetMap:    make(map[string]IpSet),
			WorkerEpMap: make(map[string]PolicyWorkerEndPoint),
			PolicyLock:  &sync.Mutex{}}
	})
}
