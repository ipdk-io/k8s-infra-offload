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
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/ipdk-io/k8s-infra-offload/pkg/types"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var (
	testTempDir string
	testPool    []*Resource
)

func TestPool(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "pool Test Suite")
}

var _ = BeforeSuite(func() {
	var err error
	testTempDir, err = ioutil.TempDir("", "pool-test-dir")
	Expect(err).ToNot(HaveOccurred())
})

var _ = AfterSuite(func() {
	err := os.RemoveAll(testTempDir)
	Expect(err).ToNot(HaveOccurred())
})

var _ = Describe("pool", func() {
	var _ = BeforeEach(func() {
		testPool = append(testPool, &Resource{
			InUse: false,
			InterfaceInfo: &types.InterfaceInfo{
				InterfaceName: "iface0",
				MacAddr:       "de:ad:be:ef:ca:fe",
				PciAddr:       " 0002:00:00.0",
				VfID:          0,
			},
		})
		testPool = append(testPool, &Resource{
			InUse: false,
			InterfaceInfo: &types.InterfaceInfo{
				InterfaceName: "iface1",
				MacAddr:       "de:ad:be:ef:ca:ff",
				PciAddr:       " 0002:00:00.1",
				VfID:          0,
			},
		})
	})

	var _ = AfterEach(func() {
		testPool = testPool[:0]
	})

	var _ = Context("Save() should", func() {
		var _ = It("store ResourcePool to file in JSON format", func() {
			path := path.Join(testTempDir, "test_data.json")
			rp := &resourcePool{Pool: testPool}
			err := rp.Save(path)
			Expect(err).ToNot(HaveOccurred())
			lrp, err := Load(path)
			Expect(err).ToNot(HaveOccurred())
			Expect(lrp).To(Equal(rp))
		})
	})

	var _ = Context("Load() should", func() {
		var _ = It("return error if cannot read JSON file (e.g. it does not exist)", func() {
			path := path.Join(testTempDir, "not_existing.json")
			_, err := Load(path)
			Expect(err).To(HaveOccurred())
		})

		var _ = It("return error if JSON data is corrupted", func() {
			path := path.Join(testTempDir, "corrupted.json")
			f, err := os.Create(path)
			Expect(err).ToNot(HaveOccurred())

			_, err = f.WriteString("{corrupted json}")
			Expect(err).ToNot(HaveOccurred())
			f.Close()

			_, err = Load(path)
			Expect(err).To(HaveOccurred())
		})
	})

	var _ = Context("Get() should", func() {
		var _ = It("return first resource", func() {
			rp := resourcePool{Pool: testPool}
			r, err := rp.Get()
			Expect(err).ToNot(HaveOccurred())
			Expect(r.InterfaceInfo.InterfaceName).To(Equal("iface0"))
		})

		var _ = It("return error if no resouces left", func() {
			rp := resourcePool{Pool: testPool}
			r, err := rp.Get()
			Expect(err).ToNot(HaveOccurred())
			Expect(r.InterfaceInfo.InterfaceName).To(Equal("iface0"))

			r1, err := rp.Get()
			Expect(err).ToNot(HaveOccurred())
			Expect(r1.InterfaceInfo.InterfaceName).To(Equal("iface1"))

			r2, err := rp.Get()
			Expect(err).To(HaveOccurred())
			Expect(r2).To(BeNil())
		})
	})

	var _ = Context("Release() should", func() {
		var _ = It("return set InUse to false and allow to reuse resource", func() {
			rp := resourcePool{Pool: testPool}
			r, err := rp.Get()
			Expect(err).ToNot(HaveOccurred())
			Expect(r.InterfaceInfo.InterfaceName).To(Equal("iface0"))

			r1, err := rp.Get()
			Expect(err).ToNot(HaveOccurred())
			Expect(r1.InterfaceInfo.InterfaceName).To(Equal("iface1"))

			rp.Release(r1.InterfaceInfo.InterfaceName)

			r2, err := rp.Get()
			Expect(err).ToNot(HaveOccurred())
			Expect(r2.InterfaceInfo.InterfaceName).To(Equal("iface1"))
		})
	})

	var _ = Context("NewResourcePool() should", func() {
		var _ = It("return ResourcePool with one element", func() {
			t := []*types.InterfaceInfo{{
				InterfaceName: "iface0",
			}}
			rp := NewResourcePool(t, "")
			r, err := rp.Get()
			Expect(err).ToNot(HaveOccurred())
			Expect(r.InterfaceInfo.InterfaceName).To(Equal("iface0"))
			Expect(r.InUse).To(BeTrue())
		})

		var _ = It("return ResourcePool with one in use element and one available element", func() {
			t := []*types.InterfaceInfo{
				{InterfaceName: "iface0"},
				{InterfaceName: "iface1"},
			}
			t1 := &types.InterfaceInfo{
				InterfaceName: "iface1",
			}
			bs, err := json.Marshal(t1)
			Expect(err).ToNot(HaveOccurred())
			p := path.Join(testTempDir, "test-cache-1")
			err = os.MkdirAll(p, 0700)
			Expect(err).NotTo(HaveOccurred())
			cache := path.Join(p, "test-t1")
			err = os.WriteFile(cache, bs, 0755)
			Expect(err).ToNot(HaveOccurred())

			rp := NewResourcePool(t, p)
			Expect(rp.(*resourcePool).Pool).ToNot(BeEmpty())
			Expect(len(rp.(*resourcePool).Pool)).To(Equal(2))
			res := rp.(*resourcePool).Pool[1]
			Expect(res.InUse).To(BeTrue())
		})
	})
})
