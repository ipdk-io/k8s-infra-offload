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

package pool

import (
	"encoding/json"
	"errors"
	"os"
	"sync"

	"github.com/ipdk-io/k8s-infra-offload/pkg/types"
)

type ResourcePool interface {
	Get() (*Resource, error)
	Release(res string)
	Save(path string) error
}

type Resource struct {
	InterfaceInfo *types.InterfaceInfo `json:"interfaceinfo"`
	InUse         bool                 `json:"inuse"`
}

type resourcePool struct {
	Pool []*Resource `json:"pool"`
	sync.Mutex
}

func NewResourcePool(resources []*types.InterfaceInfo) ResourcePool {
	pool := make([]*Resource, 0)
	for _, r := range resources {
		res := &Resource{InterfaceInfo: r, InUse: false}
		pool = append(pool, res)
	}
	return &resourcePool{Pool: pool}
}

func (p *resourcePool) Get() (*Resource, error) {
	p.Lock()
	defer p.Unlock()
	for _, r := range p.Pool {
		if !r.InUse {
			r.InUse = true
			return r, nil
		}
	}
	return nil, errors.New("no free resources left")
}

func (p *resourcePool) Release(intfName string) {
	p.Lock()
	defer p.Unlock()
	for _, r := range p.Pool {
		if intfName == r.InterfaceInfo.InterfaceName {
			r.InUse = false
			break
		}
	}
}

func (p *resourcePool) Save(path string) error {
	bs, err := json.Marshal(p)
	if err != nil {
		return err
	}

	return os.WriteFile(path, bs, 0644)
}

func Load(path string) (ResourcePool, error) {
	bs, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := &resourcePool{}
	if err := json.Unmarshal(bs, pool); err != nil {
		return nil, err
	}
	return pool, nil
}
