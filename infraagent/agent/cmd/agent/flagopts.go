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

package agent

import (
	"fmt"
	"strings"
)

// flagOpts implements pflag.Value interface.
type flagOpts struct {
	Allowed []string
	Value   string
}

// newFlagOpts gives a list of allowed flag parameters, where the second argument is the default
func newFlagOpts(allowed []string, d string) *flagOpts {
	return &flagOpts{
		Allowed: allowed,
		Value:   d,
	}
}

func (f flagOpts) String() string {
	return f.Value
}

func (f *flagOpts) Set(p string) error {
	for _, opt := range f.Allowed {
		if p == opt {
			f.Value = p
			return nil
		}
	}

	return fmt.Errorf("%s is not included in %s", p, strings.Join(f.Allowed, ","))
}

func (f *flagOpts) Type() string {
	return "string"
}
