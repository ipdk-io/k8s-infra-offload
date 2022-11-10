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
	"sync"
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
	ClusterPort     uint32
	GroupID         uint32
	ServiceEndPoint map[string]ServiceEndPoint
}

type ServiceEndPoint struct {
	IpAddress string
	port      uint32
	MemberID  uint32
}

type ServiceCollection struct {
	ServiceMap  map[string]Service
	ServiceLock *sync.Mutex
}

var ServiceSet *ServiceCollection
var EndPointSet *EndPointCollection
var once sync.Once

func NewEndPoint() {
	once.Do(func() {
		EndPointSet = &EndPointCollection{EndPointMap: make(map[string]EndPoint),
			EndPointLock: &sync.Mutex{}} //call this from core manager before setting pipeline
	})
}

func NewService() {
	once.Do(func() {
		ServiceSet = &ServiceCollection{ServiceMap: make(map[string]Service),
			ServiceLock: &sync.Mutex{}}
	})
}
