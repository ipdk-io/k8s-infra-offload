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

package netconf

import (
	"github.com/ipdk-io/k8s-infra-offload/pkg/types"
	log "github.com/sirupsen/logrus"
)

func NewPodInterface(t string, log *log.Entry) (types.PodInterface, error) {
	switch t {
	case types.IpvlanPodInterface:
		return NewIpvlanPodInterface(log)
	case types.SriovPodInterface:
		return NewSriovPodInterface(log)
	case types.TapInterface:
		return NewTapPodInterface(log)
	case types.CDQInterface:
		return NewCDQInterface(log)
	}
	log.Errorf("invalid or unsupported interface type: %s", t)
	return nil, nil
}
