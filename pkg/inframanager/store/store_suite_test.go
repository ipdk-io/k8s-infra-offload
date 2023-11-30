package store_test

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/ipdk-io/k8s-infra-offload/pkg/inframanager/p4"
	"github.com/ipdk-io/k8s-infra-offload/pkg/inframanager/store"
)

var (
	tempDir string
)

func TestStore(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Store Suite")
}

func fakemarshal(v interface{}, p string, i string) ([]byte, error) {
	return []byte{}, errors.New("Marshalling failed")
}

func fakewritefile(fn string, data []byte, permission fs.FileMode) error {
	return errors.New("Writing to file failed")
}

func fakereadfile(fn string) ([]byte, error) {
	return []byte{}, errors.New("Reading from file failed")
}

func fakeopenfile(name string, flag int, perm fs.FileMode) (*os.File, error) {
	return nil, errors.New("failed to open file")
}

func fakeunmarshal(data []byte, v interface{}) error {
	return errors.New("failed to unmarshal")
}

var _ = Describe("Storeendpoint", func() {

	Describe("IsEndPointStoreEmpty", func() {

		Context("checks if endpoint map is empty or not", func() {

			BeforeEach(func() {
				store.NewEndPoint()
				var err error
				tempDir, err = os.MkdirTemp("", "test")
				Expect(err).ShouldNot(HaveOccurred())
				store.StorePath = path.Join(tempDir, "inframanager")
				store.StoreEpFile = path.Join(store.StorePath, "cni_db.json")
			})

			AfterEach(func() {
				_ = os.RemoveAll(tempDir)
			})

			It("returns true if map is invalid or is empty", func() {
				ret := store.IsEndPointStoreEmpty()
				Expect(ret).To(Equal(true))
			})

			It("returns false when map is valid and not empty", func() {
				data_valid := store.EndPoint{
					PodIpAddress:  "10.10.10.1",
					InterfaceID:   1,
					PodMacAddress: "00:00:00:aa:aa:aa",
				}
				data_valid.WriteToStore()
				ret := store.IsEndPointStoreEmpty()
				Expect(ret).To(Equal(false))
			})

		})

	})

	Describe("InitEndPointStore", func() {

		restoreopenfile := store.NewOpenFile
		restorereadfile := store.NewReadFile
		restorejsonunmarshal := store.JsonUnmarshal

		Context("Initializes store for cni add", func() {

			BeforeEach(func() {
				var err error
				tempDir, err = os.MkdirTemp("", "test")
				Expect(err).ShouldNot(HaveOccurred())
				store.StorePath = path.Join(tempDir, "inframanager")
				store.StoreEpFile = path.Join(store.StorePath, "cni_db.json")
			})

			AfterEach(func() {
				store.NewOpenFile = restoreopenfile
				store.NewReadFile = restorereadfile
				store.JsonUnmarshal = restorejsonunmarshal
				_ = os.RemoveAll(tempDir)
			})

			It("returns true if flag is true/false", func() {
				ret := store.InitEndPointStore(false)
				Expect(ret).To(Equal(true))
			})

			It("returns false if file open fails", func() {
				store.NewOpenFile = fakeopenfile
				ret := store.InitEndPointStore(true)
				Expect(ret).To(Equal(false))
			})

			It("returns false if reading from file fails", func() {
				store.NewReadFile = fakereadfile
				ret := store.InitEndPointStore(true)
				Expect(ret).To(Equal(false))
			})

			It("returns false if unmarshal fails", func() {
				store.JsonUnmarshal = fakeunmarshal
				store.NewEndPoint()
				data_valid := store.EndPoint{
					PodIpAddress:  "10.10.10.2",
					InterfaceID:   2,
					PodMacAddress: "00:00:00:aa:aa:aa",
				}
				data_valid.WriteToStore()
				err1 := os.Mkdir(store.StorePath, 0755)
				Expect(err1).ShouldNot(HaveOccurred())
				file, err := restoreopenfile(store.StoreEpFile, os.O_CREATE, 0755)
				Expect(err).ShouldNot(HaveOccurred())
				file.Close()
				store.RunSyncEndPointInfo()
				ret := store.InitEndPointStore(false)
				Expect(ret).To(Equal(false))
			})

		})

	})

	Describe("WriteToStore", func() {

		Context("writes data to the store", func() {

			BeforeEach(func() {
				store.NewEndPoint()
				var err error
				tempDir, err = os.MkdirTemp("", "test")
				Expect(err).ShouldNot(HaveOccurred())
				store.StorePath = path.Join(tempDir, "inframanager")
				store.StoreEpFile = path.Join(store.StorePath, "cni_db.json")
			})

			It("writes the data to the store if data is valid and returns true", func() {
				data_valid := store.EndPoint{
					PodIpAddress:  "10.10.10.2",
					InterfaceID:   2,
					PodMacAddress: "00:00:00:aa:aa:aa",
				}
				ret := data_valid.WriteToStore()
				Expect(ret).To(Equal(true))
			})

			It("returns error if pod ip is invalid", func() {
				data_invalid1 := store.EndPoint{
					PodIpAddress:  "10.df.90.jh",
					InterfaceID:   1,
					PodMacAddress: "00:00:00:aa:aa:aa",
				}
				ret := data_invalid1.WriteToStore()
				Expect(ret).To(Equal(false))
			})

			It("returns error if mac is invalid", func() {
				data_invalid3 := store.EndPoint{
					PodIpAddress:  "10.10.10.1",
					InterfaceID:   1,
					PodMacAddress: "10.10.10.1",
				}
				ret := data_invalid3.WriteToStore()
				Expect(ret).To(Equal(false))
			})

		})

	})

	Describe("DeleteFromStore", func() {

		Context("Deletes data from the store", func() {

			BeforeEach(func() {
				store.NewEndPoint()
				var err error
				tempDir, err = os.MkdirTemp("", "test")
				Expect(err).ShouldNot(HaveOccurred())
				store.StorePath = path.Join(tempDir, "inframanager")
				store.StoreEpFile = path.Join(store.StorePath, "cni_db.json")
			})

			It("Deletes the data from the store and returns true if data is valid and is present in the store", func() {
				data_valid := store.EndPoint{
					PodIpAddress:  "10.10.10.1",
					InterfaceID:   1,
					PodMacAddress: "00:00:00:aa:aa:aa",
				}
				data_valid.WriteToStore()
				ret := data_valid.DeleteFromStore()
				Expect(ret).To(Equal(true))
			})

			It("returns error when pod ip address is invalid", func() {
				data_invalid1 := store.EndPoint{
					PodIpAddress:  "10.df.90.jh",
					InterfaceID:   1,
					PodMacAddress: "00:00:00:aa:aa:aa",
				}
				ret := data_invalid1.DeleteFromStore()
				Expect(ret).To(Equal(false))
			})

		})

	})

	Describe("GetFromStore", func() {

		Context("Gets the data from store", func() {

			BeforeEach(func() {
				store.NewEndPoint()
				var err error
				tempDir, err = os.MkdirTemp("", "test")
				Expect(err).ShouldNot(HaveOccurred())
				store.StorePath = path.Join(tempDir, "inframanager")
				store.StoreEpFile = path.Join(store.StorePath, "cni_db.json")
			})

			It("Gets the data from the store and returns true when input is valid", func() {
				data_valid := store.EndPoint{
					PodIpAddress:  "10.10.10.1",
					InterfaceID:   1,
					PodMacAddress: "00:00:00:aa:aa:aa",
				}
				data_valid.WriteToStore()
				ret := data_valid.GetFromStore()
				Expect(ret).To(Equal(data_valid))
			})

			It("returns nil when pod ip address is invalid", func() {
				data_invalid1 := store.EndPoint{
					PodIpAddress:  "10.df.90.jh",
					InterfaceID:   1,
					PodMacAddress: "00:00:00:aa:aa:aa",
				}
				ret := data_invalid1.GetFromStore()
				Expect(ret).Should(BeNil())
			})

			It("returns nil when input is valid but data is not present", func() {
				data_no_hit := store.EndPoint{
					PodIpAddress:  "10.10.10.8",
					InterfaceID:   4,
					PodMacAddress: "00:00:00:aa:aa:aa",
				}
				ret := data_no_hit.GetFromStore()
				Expect(ret).Should(BeNil())
			})

		})

	})

	Describe("RunSyncEndPointInfo", func() {

		Context("Writes to persistent storage", func() {

			restorewritefile := store.NewWriteFile
			restoremarshalindent := store.JsonMarshalIndent

			BeforeEach(func() {
				store.NewEndPoint()
				var err error
				tempDir, err = os.MkdirTemp("", "test")
				Expect(err).ShouldNot(HaveOccurred())
				store.StorePath = path.Join(tempDir, "inframanager")
				store.StoreEpFile = path.Join(store.StorePath, "cni_db.json")
				data_valid := store.EndPoint{
					PodIpAddress:  "10.10.10.4",
					InterfaceID:   4,
					PodMacAddress: "00:00:00:aa:aa:aa",
				}
				data_valid.WriteToStore()
				err1 := os.Mkdir(store.StorePath, 0755)
				Expect(err1).ShouldNot(HaveOccurred())
			})

			AfterEach(func() {
				store.NewWriteFile = restorewritefile
				store.JsonMarshalIndent = restoremarshalindent
				_ = os.RemoveAll(tempDir)
			})

			It("returns true", func() {
				ret := store.RunSyncEndPointInfo()
				Expect(ret).To(Equal(true))
			})

			It("returns false if write to file fails", func() {
				store.NewWriteFile = fakewritefile
				ret := store.RunSyncEndPointInfo()
				Expect(ret).To(Equal(false))
			})

			It("returns false if marshal fails", func() {
				store.JsonMarshalIndent = fakemarshal
				ret := store.RunSyncEndPointInfo()
				Expect(ret).To(Equal(false))
			})

		})

	})

})

var _ = Describe("Storeservice", func() {

	Describe("IsServiceStoreEmpty", func() {

		Context("checks if service map is empty or not", func() {

			BeforeEach(func() {
				store.NewService()
				var err error
				tempDir, err = os.MkdirTemp("", "test")
				Expect(err).ShouldNot(HaveOccurred())
				store.StorePath = path.Join(tempDir, "inframanager")
				store.ServicesFile = path.Join(store.StorePath, "services_db.json")
			})

			AfterEach(func() {
				_ = os.RemoveAll(tempDir)
			})

			It("returns true if map is invalid or is empty", func() {
				ret := store.IsServiceStoreEmpty()
				Expect(ret).To(Equal(true))
			})

			It("returns false if map is valid and not empty", func() {
				ep1 := store.ServiceEndPoint{
					IpAddress: "10.10.10.1",
					Port:      8081,
					MemberID:  1,
				}
				ep2 := store.ServiceEndPoint{
					IpAddress: "10.10.10.2",
					Port:      8082,
					MemberID:  2,
				}
				data_valid := store.Service{
					ClusterIp:       "10.100.0.1",
					Port:            10000,
					Proto:           "TCP",
					GroupID:         1,
					ServiceEndPoint: make(map[string]store.ServiceEndPoint),
				}
				data_valid.ServiceEndPoint["10.10.10.1"] = ep1
				data_valid.ServiceEndPoint["10.10.10.2"] = ep2
				data_valid.WriteToStore()
				ret := store.IsServiceStoreEmpty()
				Expect(ret).To(Equal(false))
			})

		})

	})

	Describe("InitServiceStore", func() {

		restoreopenfile := store.NewOpenFile
		restorereadfile := store.NewReadFile
		restorejsonunmarshal := store.JsonUnmarshal

		Context("Initializes store for service", func() {

			BeforeEach(func() {
				store.NewService()
				var err error
				tempDir, err = os.MkdirTemp("", "test")
				Expect(err).ShouldNot(HaveOccurred())
				store.StorePath = path.Join(tempDir, "inframanager")
				store.ServicesFile = path.Join(store.StorePath, "services_db.json")
			})

			AfterEach(func() {
				store.NewOpenFile = restoreopenfile
				store.NewReadFile = restorereadfile
				store.JsonUnmarshal = restorejsonunmarshal
				_ = os.RemoveAll(tempDir)
			})

			It("returns true when the flag is true/false", func() {
				ret := store.InitServiceStore(false)
				Expect(ret).To(Equal(true))
			})

			It("returns false if file open fails", func() {
				store.NewOpenFile = fakeopenfile
				ret := store.InitServiceStore(true)
				Expect(ret).To(Equal(false))
			})

			It("returns false if reading from file fails", func() {
				store.NewReadFile = fakereadfile
				ret := store.InitServiceStore(true)
				Expect(ret).To(Equal(false))
			})

			It("returns false if unmarshal fails", func() {
				store.JsonUnmarshal = fakeunmarshal
				ep1 := store.ServiceEndPoint{
					IpAddress: "10.10.10.1",
					Port:      8081,
					MemberID:  1,
				}
				ep2 := store.ServiceEndPoint{
					IpAddress: "10.10.10.2",
					Port:      8082,
					MemberID:  2,
				}
				data_valid := store.Service{
					ClusterIp:       "10.100.0.1",
					Port:            10000,
					Proto:           "TCP",
					GroupID:         1,
					ServiceEndPoint: make(map[string]store.ServiceEndPoint),
				}
				data_valid.ServiceEndPoint["10.10.10.1"] = ep1
				data_valid.ServiceEndPoint["10.10.10.2"] = ep2
				data_valid.WriteToStore()
				err1 := os.Mkdir(store.StorePath, 0755)
				Expect(err1).ShouldNot(HaveOccurred())
				file, err := restoreopenfile(store.ServicesFile, os.O_CREATE, 0755)
				Expect(err).ShouldNot(HaveOccurred())
				file.Close()
				store.RunSyncServiceInfo()
				ret := store.InitServiceStore(false)
				Expect(ret).To(Equal(false))
			})

		})

	})

	Describe("WriteToStore", func() {

		Context("writes data to the store", func() {

			BeforeEach(func() {
				store.NewService()
				var err error
				tempDir, err = os.MkdirTemp("", "test")
				Expect(err).ShouldNot(HaveOccurred())
				store.StorePath = path.Join(tempDir, "inframanager")
				store.ServicesFile = path.Join(store.StorePath, "services_db.json")
			})

			AfterEach(func() {
				_ = os.RemoveAll(tempDir)
			})

			/*It("returns false if getkey fails", func() {
				ep1 := store.ServiceEndPoint{
					IpAddress: "10.10.10.1",
					Port:      8081,
					MemberID:  1,
				}
				ep2 := store.ServiceEndPoint{
					IpAddress: "10.10.10.2",
					Port:      8082,
					MemberID:  2,
				}
				data_invalidkey := store.Service{
					ClusterIp:       "10.100.0.4",
					Port:            70000,
					Proto:           "TCP",
					GroupID:         1,
					ServiceEndPoint: make(map[string]store.ServiceEndPoint),
				}
				data_invalidkey.ServiceEndPoint["10.10.10.1"] = ep1
				data_invalidkey.ServiceEndPoint["10.10.10.2"] = ep2
				ret := data_invalidkey.WriteToStore()
				Expect(ret).To(Equal(false))
			})*/

			It("writes data to the store and returns true when input is valid", func() {
				ep1 := store.ServiceEndPoint{
					IpAddress: "10.10.10.1",
					Port:      8081,
					MemberID:  1,
				}
				ep2 := store.ServiceEndPoint{
					IpAddress: "10.10.10.2",
					Port:      8082,
					MemberID:  2,
				}
				data_valid := store.Service{
					ClusterIp:       "10.100.0.4",
					Port:            10004,
					Proto:           "TCP",
					GroupID:         1,
					ServiceEndPoint: make(map[string]store.ServiceEndPoint),
				}
				data_valid.ServiceEndPoint["10.10.10.1"] = ep1
				data_valid.ServiceEndPoint["10.10.10.2"] = ep2
				ret := data_valid.WriteToStore()
				Expect(ret).To(Equal(true))
			})

			It("writes data to the store and returns false when input is invalid", func() {
				ep1 := store.ServiceEndPoint{
					IpAddress: "10.10.10.1",
					Port:      8081,
					MemberID:  1,
				}
				ep2 := store.ServiceEndPoint{
					IpAddress: "10.10.10.2",
					Port:      8082,
					MemberID:  2,
				}
				data_invalid := store.Service{
					ClusterIp:       "a.b.c.d",
					Port:            10000,
					Proto:           "UDP",
					GroupID:         1,
					ServiceEndPoint: make(map[string]store.ServiceEndPoint),
				}
				data_invalid.ServiceEndPoint["10.10.10.1"] = ep1
				data_invalid.ServiceEndPoint["10.10.10.2"] = ep2
				ret := data_invalid.WriteToStore()
				Expect(ret).To(Equal(false))
			})

		})

	})

	Describe("DeleteFromStore", func() {

		Context("Deletes data from store", func() {

			BeforeEach(func() {
				store.NewService()
				var err error
				tempDir, err = os.MkdirTemp("", "test")
				Expect(err).ShouldNot(HaveOccurred())
				store.StorePath = path.Join(tempDir, "inframanager")
				store.ServicesFile = path.Join(store.StorePath, "services_db.json")
			})

			AfterEach(func() {
				_ = os.RemoveAll(tempDir)
			})

			/*It("returns false if getkey fails", func() {
				ep1 := store.ServiceEndPoint{
					IpAddress: "10.10.10.1",
					Port:      8081,
					MemberID:  1,
				}
				ep2 := store.ServiceEndPoint{
					IpAddress: "10.10.10.2",
					Port:      8082,
					MemberID:  2,
				}
				data_invalidkey := store.Service{
					ClusterIp:       "10.100.0.4",
					Port:            70000,
					Proto:           "TCP",
					GroupID:         1,
					ServiceEndPoint: make(map[string]store.ServiceEndPoint),
				}
				data_invalidkey.ServiceEndPoint["10.10.10.1"] = ep1
				data_invalidkey.ServiceEndPoint["10.10.10.2"] = ep2
				data_invalidkey.WriteToStore()
				ret := data_invalidkey.DeleteFromStore()
				Expect(ret).To(Equal(false))
			})*/

			It("deletes data from the store and returns true when input is valid and is present in the store", func() {
				ep1 := store.ServiceEndPoint{
					IpAddress: "10.10.10.1",
					Port:      8081,
					MemberID:  1,
				}
				ep2 := store.ServiceEndPoint{
					IpAddress: "10.10.10.2",
					Port:      8082,
					MemberID:  2,
				}
				data_valid := store.Service{
					ClusterIp:       "10.100.0.1",
					Port:            10000,
					Proto:           "TCP",
					GroupID:         1,
					ServiceEndPoint: make(map[string]store.ServiceEndPoint),
				}
				data_valid.ServiceEndPoint["10.10.10.1"] = ep1
				data_valid.ServiceEndPoint["10.10.10.2"] = ep2
				data_valid.WriteToStore()
				ret := data_valid.DeleteFromStore()
				Expect(ret).To(Equal(true))
			})

			It("returns false when input is invalid", func() {
				ep1 := store.ServiceEndPoint{
					IpAddress: "10.10.10.1",
					Port:      8081,
					MemberID:  1,
				}
				ep2 := store.ServiceEndPoint{
					IpAddress: "10.10.10.2",
					Port:      8082,
					MemberID:  2,
				}
				data_invalid := store.Service{
					ClusterIp:       "a.100.0.b",
					Port:            10003,
					Proto:           "TCP",
					GroupID:         3,
					ServiceEndPoint: make(map[string]store.ServiceEndPoint),
				}
				data_invalid.ServiceEndPoint["10.10.10.1"] = ep1
				data_invalid.ServiceEndPoint["10.10.10.2"] = ep2
				ret := data_invalid.DeleteFromStore()
				Expect(ret).To(Equal(false))
			})

		})

	})

	Describe("GetFromStore", func() {

		Context("gets data from the store", func() {

			BeforeEach(func() {
				store.NewService()
				var err error
				tempDir, err = os.MkdirTemp("", "test")
				Expect(err).ShouldNot(HaveOccurred())
				store.StorePath = path.Join(tempDir, "inframanager")
				store.ServicesFile = path.Join(store.StorePath, "services_db.json")
			})

			AfterEach(func() {
				_ = os.RemoveAll(tempDir)
			})

			It("gets data from the store and returns true when input is valid and is present in the store", func() {
				ep1 := store.ServiceEndPoint{
					IpAddress: "10.10.10.1",
					Port:      8081,
					MemberID:  1,
				}
				ep2 := store.ServiceEndPoint{
					IpAddress: "10.10.10.2",
					Port:      8082,
					MemberID:  2,
				}
				data_valid := store.Service{
					ClusterIp:       "10.100.0.1",
					Port:            10000,
					Proto:           "TCP",
					GroupID:         1,
					ServiceEndPoint: make(map[string]store.ServiceEndPoint),
				}
				data_valid.ServiceEndPoint["10.10.10.1"] = ep1
				data_valid.ServiceEndPoint["10.10.10.2"] = ep2
				data_valid.WriteToStore()
				ret := data_valid.GetFromStore()
				Expect(ret).To(Equal(data_valid))
			})

			It("returns false when input is valid but not present in the store", func() {
				ep1 := store.ServiceEndPoint{
					IpAddress: "10.10.10.1",
					Port:      8081,
					MemberID:  1,
				}
				ep2 := store.ServiceEndPoint{
					IpAddress: "10.10.10.2",
					Port:      8082,
					MemberID:  2,
				}
				data_valid := store.Service{
					ClusterIp:       "10.100.0.3",
					Port:            10003,
					Proto:           "TCP",
					GroupID:         3,
					ServiceEndPoint: make(map[string]store.ServiceEndPoint),
				}
				data_valid.ServiceEndPoint["10.10.10.1"] = ep1
				data_valid.ServiceEndPoint["10.10.10.2"] = ep2
				ret := data_valid.GetFromStore()
				Expect(ret).Should(BeNil())
			})

			It("returns nil when input is invalid", func() {
				ep1 := store.ServiceEndPoint{
					IpAddress: "10.10.10.1",
					Port:      8081,
					MemberID:  1,
				}
				ep2 := store.ServiceEndPoint{
					IpAddress: "10.10.10.2",
					Port:      8082,
					MemberID:  2,
				}
				data_invalid := store.Service{
					ClusterIp:       "a.100.0.b",
					Port:            10000,
					Proto:           "TCP",
					GroupID:         1,
					ServiceEndPoint: make(map[string]store.ServiceEndPoint),
				}
				data_invalid.ServiceEndPoint["10.10.10.1"] = ep1
				data_invalid.ServiceEndPoint["10.10.10.2"] = ep2
				ret := data_invalid.GetFromStore()
				Expect(ret).Should(BeNil())
			})

		})

	})

	Describe("UpdateToStore", func() {

		Context("updates data to the store", func() {

			BeforeEach(func() {
				store.NewService()
				var err error
				tempDir, err = os.MkdirTemp("", "test")
				Expect(err).ShouldNot(HaveOccurred())
				store.StorePath = path.Join(tempDir, "inframanager")
				store.ServicesFile = path.Join(store.StorePath, "services_db.json")
			})

			AfterEach(func() {
				_ = os.RemoveAll(tempDir)
			})

			It("returns false if get from store fails", func() {
				ep1 := store.ServiceEndPoint{
					IpAddress: "10.10.10.1",
					Port:      8081,
					MemberID:  1,
				}
				ep2 := store.ServiceEndPoint{
					IpAddress: "10.10.10.2",
					Port:      8082,
					MemberID:  2,
				}
				data_invalid := store.Service{
					ClusterIp:       "10.100.0.1",
					Port:            10000,
					GroupID:         1,
					ServiceEndPoint: make(map[string]store.ServiceEndPoint),
				}
				data_invalid.ServiceEndPoint["10.10.10.1"] = ep1
				data_invalid.ServiceEndPoint["10.10.10.2"] = ep2
				ret := data_invalid.UpdateToStore()
				Expect(ret).To(Equal(false))
			})

			It("returns true if data is valid and update to store succeeds", func() {
				ep1 := store.ServiceEndPoint{
					IpAddress: "10.10.10.1",
					Port:      8081,
					MemberID:  1,
				}
				ep2 := store.ServiceEndPoint{
					IpAddress: "10.10.10.2",
					Port:      8082,
					MemberID:  2,
				}
				data_valid := store.Service{
					ClusterIp:       "10.100.0.8",
					Port:            10000,
					Proto:           "TCP",
					GroupID:         1,
					ServiceEndPoint: make(map[string]store.ServiceEndPoint),
				}
				data_valid.ServiceEndPoint["10.10.10.1"] = ep1
				data_valid.ServiceEndPoint["10.10.10.2"] = ep2
				data_valid.WriteToStore()
				ep3 := store.ServiceEndPoint{
					IpAddress: "10.10.10.3",
					Port:      8083,
					MemberID:  3,
				}
				data_valid.ServiceEndPoint["10.10.10.3"] = ep3
				ret := data_valid.UpdateToStore()
				Expect(ret).To(Equal(true))
			})

		})

	})

	Describe("RunSyncServiceInfo", func() {

		restorewritefile := store.NewWriteFile
		restorejsonmarshalindent := store.JsonMarshalIndent

		Context("Writes to persistent storage", func() {

			BeforeEach(func() {
				store.NewService()
				var err error
				tempDir, err = os.MkdirTemp("", "test")
				Expect(err).ShouldNot(HaveOccurred())
				store.StorePath = path.Join(tempDir, "inframanager")
				store.ServicesFile = path.Join(store.StorePath, "services_db.json")
				ep1 := store.ServiceEndPoint{
					IpAddress: "10.10.10.1",
					Port:      8081,
					MemberID:  1,
				}
				ep2 := store.ServiceEndPoint{
					IpAddress: "10.10.10.2",
					Port:      8082,
					MemberID:  2,
				}
				data_valid := store.Service{
					ClusterIp:       "10.100.0.1",
					Port:            10000,
					Proto:           "TCP",
					GroupID:         1,
					ServiceEndPoint: make(map[string]store.ServiceEndPoint),
				}
				data_valid.ServiceEndPoint["10.10.10.1"] = ep1
				data_valid.ServiceEndPoint["10.10.10.2"] = ep2
				data_valid.WriteToStore()
				err1 := os.Mkdir(store.StorePath, 0755)
				Expect(err1).ShouldNot(HaveOccurred())
			})

			AfterEach(func() {
				store.NewWriteFile = restorewritefile
				store.JsonMarshalIndent = restorejsonmarshalindent
				_ = os.RemoveAll(tempDir)
			})

			It("returns true", func() {
				ret := store.RunSyncServiceInfo()
				Expect(ret).To(Equal(true))
			})

			It("returns false if write to file fails", func() {
				store.NewWriteFile = fakewritefile
				ret := store.RunSyncServiceInfo()
				Expect(ret).To(Equal(false))
			})

			It("returns false if marshal fails", func() {
				store.JsonMarshalIndent = fakemarshal
				ret := store.RunSyncServiceInfo()
				Expect(ret).To(Equal(false))
			})

		})

	})

})

var _ = Describe("Storepolicy", func() {

	Describe("IsPolicyStoreEmpty()", func() {

		Context("checks if Policy store map is empty or not", func() {

			BeforeEach(func() {
				store.NewPolicy()
				var err error
				tempDir, err = os.MkdirTemp("", "test")
				Expect(err).ShouldNot(HaveOccurred())
				store.StorePath = path.Join(tempDir, "inframanager")
				store.PolicyFile = path.Join(store.StorePath, "policy_db.json")
			})

			AfterEach(func() {
				_ = os.RemoveAll(tempDir)
			})

			It("returns true if map is invalid or is empty", func() {
				ret := store.IsPolicyStoreEmpty()
				Expect(ret).To(Equal(true))
			})

			It("returns false when map is valid and not empty", func() {
				r1 := store.Rule{
					Id:        "rule1",
					PortRange: []uint16{80, 443},
					RuleMask:  0xff,
					Cidr:      "192.168.1.0/24",
					IpSetID:   "ipset1",
				}

				ruleGroup := store.RuleGroup{
					Index:     1,
					Direction: "RX",
					Protocol:  p4.PROTO_TCP,
					Rules:     make(map[string]store.Rule),
				}
				ruleGroup.Rules["rule1"] = r1

				data_valid := store.Policy{
					Name:       "policy1",
					RuleGroups: make(map[uint16]store.RuleGroup),
				}
				data_valid.RuleGroups[1] = ruleGroup

				data_valid.WriteToStore()
				ret := store.IsPolicyStoreEmpty()
				Expect(ret).To(Equal(false))

			})
		})
	})

	Describe("IsIpsetStoreEmpty", func() {

		Context("checks if Ipset store map is empty or not", func() {

			BeforeEach(func() {
				store.NewPolicy()
				var err error
				tempDir, err = os.MkdirTemp("", "test")
				Expect(err).ShouldNot(HaveOccurred())
				store.StorePath = path.Join(tempDir, "inframanager")
				store.IpsetFile = path.Join(store.StorePath, "ipset_db.json")
			})

			AfterEach(func() {
				_ = os.RemoveAll(tempDir)
			})

			It("returns true if map is invalid or is empty", func() {
				ret := store.IsIpsetStoreEmpty()
				Expect(ret).To(Equal(true))
			})

			It("returns false when map is valid and not empty", func() {
				data_valid := store.IpSet{
					IpsetID:    "1234",
					IpSetIDx:   1,
					PolicyName: "Policy1",
					RuleID:     "RuleID01",
					IpAddr:     []string{"10.10.10.1"},
				}
				data_valid.WriteToStore()
				ret := store.IsIpsetStoreEmpty()
				Expect(ret).To(Equal(false))
			})
		})
	})

	Describe("IsWorkerepStoreEmpty", func() {

		Context("checks if WorkerEp store map is empty or not", func() {

			BeforeEach(func() {
				store.NewPolicy()
				var err error
				tempDir, err = os.MkdirTemp("", "test")
				Expect(err).ShouldNot(HaveOccurred())
				store.StorePath = path.Join(tempDir, "inframanager")
				store.WorkerepFile = path.Join(store.StorePath, "workerep_db.json")
			})

			AfterEach(func() {
				_ = os.RemoveAll(tempDir)
			})

			It("returns true if map is invalid or is empty", func() {
				ret := store.IsWorkerepStoreEmpty()
				Expect(ret).To(Equal(true))
			})

			It("returns false when map is valid and not empty", func() {
				data_valid := store.PolicyWorkerEndPoint{
					WorkerEp:          "test-pod",
					WorkerIp:          "10.10.10.1",
					PolicyNameIngress: []string{"policy1", "policy2"},
					PolicyNameEgress:  []string{"policy3", "policy4"},
				}
				ret := data_valid.WriteToStore()
				Expect(ret).To(Equal(true))
				ret = store.IsWorkerepStoreEmpty()
				Expect(ret).To(Equal(false))
			})

		})
	})

	Describe("InitPolicyStore", func() {

		restoreopenfile := store.NewOpenFile
		restorereadfile := store.NewReadFile
		restorejsonunmarshal := store.JsonUnmarshal

		Context("Initializes store for policy", func() {

			BeforeEach(func() {
				var err error
				tempDir, err = os.MkdirTemp("", "test")
				Expect(err).ShouldNot(HaveOccurred())
				store.StorePath = path.Join(tempDir, "inframanager")
				store.PolicyFile = path.Join(store.StorePath, "policy_db.json")
				store.IpsetFile = path.Join(store.StorePath, "ipset_db.json")
				store.WorkerepFile = path.Join(store.StorePath, "workerep_db.json")
			})

			AfterEach(func() {
				store.NewOpenFile = restoreopenfile
				store.NewReadFile = restorereadfile
				store.JsonUnmarshal = restorejsonunmarshal
				_ = os.RemoveAll(tempDir)
			})

			It("returns true if flag is true/false", func() {
				ret := store.InitPolicyStore(false)
				Expect(ret).To(Equal(true))
			})

			It("returns false if file open fails", func() {
				store.NewOpenFile = fakeopenfile
				ret := store.InitPolicyStore(true)
				Expect(ret).To(Equal(false))
			})

			It("returns false if reading from file fails", func() {
				store.NewReadFile = fakereadfile
				ret := store.InitPolicyStore(true)
				Expect(ret).To(Equal(false))
			})

			It("returns false if unmarshal fails", func() {
				store.JsonUnmarshal = fakeunmarshal
				store.NewPolicy()

				//Policy
				r1 := store.Rule{
					Id:        "rule1",
					PortRange: []uint16{80, 443},
					RuleMask:  0xff,
					Cidr:      "192.168.1.0/24",
					IpSetID:   "ipset1",
				}

				ruleGroup := store.RuleGroup{
					Index:     1,
					Direction: "RX",
					Protocol:  p4.PROTO_TCP,
					Rules:     make(map[string]store.Rule),
				}
				ruleGroup.Rules["rule1"] = r1

				data_valid := store.Policy{
					Name:       "policy1",
					RuleGroups: make(map[uint16]store.RuleGroup),
				}
				data_valid.RuleGroups[1] = ruleGroup
				data_valid.WriteToStore()
				err := os.Mkdir(store.StorePath, 0755)
				Expect(err).ShouldNot(HaveOccurred())
				file, err1 := restoreopenfile(store.PolicyFile, os.O_CREATE, 0755)
				Expect(err1).ShouldNot(HaveOccurred())
				file.Close()
				store.RunSyncPolicyInfo()

				//IpSet
				data_valid1 := store.IpSet{
					IpsetID:    "1234",
					IpSetIDx:   1,
					PolicyName: "Policy1",
					RuleID:     "RuleID01",
					IpAddr:     []string{"10.10.10.1"},
				}
				data_valid1.WriteToStore()
				file1, err2 := restoreopenfile(store.IpsetFile, os.O_CREATE, 0755)
				Expect(err2).ShouldNot(HaveOccurred())
				file1.Close()
				store.RunSyncIpSetInfo()

				//WorkerEndPoint
				data_valid2 := store.PolicyWorkerEndPoint{
					WorkerEp:          "test-pod",
					WorkerIp:          "10.10.10.1",
					PolicyNameIngress: []string{"policy1", "policy2"},
					PolicyNameEgress:  []string{"policy3", "policy4"},
				}
				data_valid2.WriteToStore()
				file2, err3 := restoreopenfile(store.WorkerepFile, os.O_CREATE, 0755)
				Expect(err3).ShouldNot(HaveOccurred())
				file2.Close()
				store.RunSyncWorkerEpInfo()

				ret := store.InitPolicyStore(false)
				Expect(ret).To(Equal(false))
			})

			It("returns true after running the RunSync*Info", func() {
				store.NewPolicy()

				//Policy
				r1 := store.Rule{
					Id:        "rule1",
					PortRange: []uint16{80, 443},
					RuleMask:  0xff,
					Cidr:      "192.168.1.0/24",
					IpSetID:   "ipset1",
				}

				ruleGroup := store.RuleGroup{
					Index:     1,
					Direction: "RX",
					Protocol:  p4.PROTO_TCP,
					Rules:     make(map[string]store.Rule),
				}
				ruleGroup.Rules["rule1"] = r1

				data_valid := store.Policy{
					Name:       "policy2",
					RuleGroups: make(map[uint16]store.RuleGroup),
				}
				data_valid.RuleGroups[1] = ruleGroup
				data_valid.WriteToStore()
				err := os.Mkdir(store.StorePath, 0755)
				Expect(err).ShouldNot(HaveOccurred())
				file, err1 := restoreopenfile(store.PolicyFile, os.O_CREATE, 0755)
				Expect(err1).ShouldNot(HaveOccurred())
				file.Close()
				store.RunSyncPolicyInfo()

				//IpSet
				data_valid1 := store.IpSet{
					IpsetID:    "12345",
					IpSetIDx:   1,
					PolicyName: "Policy2",
					RuleID:     "RuleID01",
					IpAddr:     []string{"10.10.10.1"},
				}
				data_valid1.WriteToStore()
				file1, err2 := restoreopenfile(store.IpsetFile, os.O_CREATE, 0755)
				Expect(err2).ShouldNot(HaveOccurred())
				file1.Close()
				store.RunSyncIpSetInfo()

				//WorkerEndPoint
				data_valid2 := store.PolicyWorkerEndPoint{
					WorkerEp:          "test-pod",
					WorkerIp:          "10.10.10.3",
					PolicyNameIngress: []string{"policy1", "policy2"},
					PolicyNameEgress:  []string{"policy3", "policy4"},
				}
				data_valid2.WriteToStore()
				file2, err3 := restoreopenfile(store.WorkerepFile, os.O_CREATE, 0755)
				Expect(err3).ShouldNot(HaveOccurred())
				file2.Close()
				store.RunSyncWorkerEpInfo()

				ret := store.InitPolicyStore(false)
				Expect(ret).To(Equal(true))
			})
		})
	})

	//policyadd : Write to Store
	Describe("WriteToStore", func() {

		Context("writes Policy data to the store", func() {

			BeforeEach(func() {
				store.NewPolicy()
				var err error
				tempDir, err = os.MkdirTemp("", "test")
				Expect(err).ShouldNot(HaveOccurred())
				store.StorePath = path.Join(tempDir, "inframanager")
				store.PolicyFile = path.Join(store.StorePath, "policy_db.json")
			})

			AfterEach(func() {
				_ = os.RemoveAll(tempDir)
			})

			//Valid case 1
			It("writes the data to the store if data is valid and returns true", func() {

				r1 := store.Rule{
					Id:        "rule1",
					PortRange: []uint16{80, 443},
					RuleMask:  0xff,
					Cidr:      "192.168.1.0/24",
					IpSetID:   "ipset1",
				}

				ruleGroup := store.RuleGroup{
					Index:     1,
					Direction: "RX",
					Protocol:  p4.PROTO_TCP,
					Rules:     make(map[string]store.Rule),
				}
				ruleGroup.Rules["rule1"] = r1

				data_valid := store.Policy{
					Name:       "policy1",
					RuleGroups: make(map[uint16]store.RuleGroup),
				}
				data_valid.RuleGroups[1] = ruleGroup

				ret := data_valid.WriteToStore()
				Expect(ret).To(Equal(true))
			})
			//Invalid case 1
			It("returns error if Cidr ip is invalid", func() {
				r1 := store.Rule{
					Id:        "rule1",
					PortRange: []uint16{80, 443},
					RuleMask:  0xff,
					Cidr:      "10.10.10.ff/44",
					IpSetID:   "ipset1",
				}

				ruleGroup := store.RuleGroup{
					Index:     1,
					Direction: "RX",
					Protocol:  p4.PROTO_TCP,
					Rules:     make(map[string]store.Rule),
				}
				ruleGroup.Rules["rule1"] = r1

				data_invalid1 := store.Policy{
					Name:       "policy1",
					RuleGroups: make(map[uint16]store.RuleGroup),
				}
				data_invalid1.RuleGroups[1] = ruleGroup

				ret := data_invalid1.WriteToStore()
				Expect(ret).To(Equal(false))
			})
			//Invalid case 2
			It("returns error if port range len is invalid", func() {
				r1 := store.Rule{
					Id:        "rule1",
					PortRange: []uint16{80, 202, 430},
					RuleMask:  0xff,
					Cidr:      "192.168.ab.cd/24",
					IpSetID:   "ipset1",
				}

				ruleGroup := store.RuleGroup{
					Index:     1,
					Direction: "RX",
					Protocol:  p4.PROTO_TCP,
					Rules:     make(map[string]store.Rule),
				}
				ruleGroup.Rules["rule1"] = r1

				data_invalid2 := store.Policy{
					Name:       "policy1",
					RuleGroups: make(map[uint16]store.RuleGroup),
				}
				data_invalid2.RuleGroups[1] = ruleGroup

				ret := data_invalid2.WriteToStore()
				Expect(ret).To(Equal(false))
			})
			//Invalid case 3
			It("Returns error if Direction is invalid", func() {
				r1 := store.Rule{
					Id:        "rule1",
					PortRange: []uint16{80, 443},
					RuleMask:  0xff,
					Cidr:      "192.168.1.0/24",
					IpSetID:   "ipset1",
				}
				ruleGroup := store.RuleGroup{
					Index:     1,
					Direction: "ingress",
					Protocol:  p4.PROTO_TCP,
					Rules:     make(map[string]store.Rule),
				}
				ruleGroup.Rules["rule1"] = r1

				data_valid3 := store.Policy{
					Name:       "policy1",
					RuleGroups: make(map[uint16]store.RuleGroup),
				}
				data_valid3.RuleGroups[1] = ruleGroup

				ret := data_valid3.WriteToStore()
				Expect(ret).To(Equal(false))
			})
		})
	})

	//ipsetadd
	Describe("WriteToStore", func() {

		Context("writes IpSet data to the store", func() {

			BeforeEach(func() {
				store.NewPolicy()
				var err error
				tempDir, err = os.MkdirTemp("", "test")
				Expect(err).ShouldNot(HaveOccurred())
				store.StorePath = path.Join(tempDir, "inframanager")
				store.IpsetFile = path.Join(store.StorePath, "ipset_db.json")
			})

			AfterEach(func() {
				_ = os.RemoveAll(tempDir)
			})

			//Valid case 1
			It("writes the data to the store if data is valid and returns true", func() {
				data_valid := store.IpSet{
					IpsetID:    "1234",
					IpSetIDx:   1,
					PolicyName: "Policy1",
					RuleID:     "RuleID",
					IpAddr:     []string{"10.10.10.1"},
				}
				ret := data_valid.WriteToStore()
				Expect(ret).To(Equal(true))
			})
			//Invalid case 1
			It("returns error if ip is invalid", func() {
				data_invalid1 := store.IpSet{
					IpsetID:    "1234",
					IpSetIDx:   1,
					PolicyName: "Policy1",
					RuleID:     "RuleID",
					IpAddr:     []string{"10.10.ab.cd"},
				}
				ret := data_invalid1.WriteToStore()
				Expect(ret).To(Equal(false))
			})
			//Invalid case 2
			It("returns error if IpSetIDx is invalid, [IpSetIDx should be 0-255]", func() {
				data_invalid2 := store.IpSet{
					IpsetID:    "1234",
					IpSetIDx:   266,
					PolicyName: "Policy1",
					RuleID:     "RuleID",
					IpAddr:     []string{"10.10.10.1"},
				}
				ret := data_invalid2.WriteToStore()
				Expect(ret).To(Equal(false))
			})
		})
	})

	//workereEp add
	Describe("WriteToStore", func() {

		Context("writes PolicyWorkerEndPoint data to the store", func() {

			BeforeEach(func() {
				store.NewPolicy()
				var err error
				tempDir, err = os.MkdirTemp("", "test")
				Expect(err).ShouldNot(HaveOccurred())
				store.StorePath = path.Join(tempDir, "inframanager")
				store.WorkerepFile = path.Join(store.StorePath, "workerep_db.json")
			})

			AfterEach(func() {
				_ = os.RemoveAll(tempDir)
			})

			//Valid case 1
			It("writes the data to the store if data is valid and returns true", func() {
				data_valid := store.PolicyWorkerEndPoint{
					WorkerEp:          "test-pod",
					WorkerIp:          "10.10.10.1",
					PolicyNameIngress: []string{"policy1", "policy2"},
					PolicyNameEgress:  []string{"policy3", "policy4"},
				}
				ret := data_valid.WriteToStore()
				Expect(ret).To(Equal(true))
			})
			//Invalid case 1
			It("returns error if WorkerEp is invalid", func() {
				data_invalid1 := store.PolicyWorkerEndPoint{
					WorkerEp:          "test-pod",
					WorkerIp:          "10.10.a.b",
					PolicyNameIngress: []string{"policy1", "policy2"},
					PolicyNameEgress:  []string{"policy3", "policy4"},
				}
				ret := data_invalid1.WriteToStore()
				Expect(ret).To(Equal(false))
			})
		})
	})

	//Policy: Delete from store
	Describe("DeleteFromStore", func() {

		Context("Deletes Policy data from the store", func() {

			BeforeEach(func() {
				store.NewPolicy()
				var err error
				tempDir, err = os.MkdirTemp("", "test")
				Expect(err).ShouldNot(HaveOccurred())
				store.StorePath = path.Join(tempDir, "inframanager")
				store.PolicyFile = path.Join(store.StorePath, "policy_db.json")
			})

			AfterEach(func() {
				_ = os.RemoveAll(tempDir)
			})

			//Valid case 1
			It("Deletes the policy data from the store and returns true if data is present in the store", func() {
				r1 := store.Rule{
					Id:        "rule1",
					PortRange: []uint16{80, 443},
					RuleMask:  0xff,
					Cidr:      "192.168.1.0/24",
					IpSetID:   "ipset1",
				}

				ruleGroup := store.RuleGroup{
					Index:     1,
					Direction: "RX",
					Protocol:  p4.PROTO_TCP,
					Rules:     make(map[string]store.Rule),
				}
				ruleGroup.Rules["rule1"] = r1

				data_valid := store.Policy{
					Name:       "policy1",
					RuleGroups: make(map[uint16]store.RuleGroup),
				}
				data_valid.RuleGroups[1] = ruleGroup
				data_valid.WriteToStore()
				ret := data_valid.DeleteFromStore()
				Expect(ret).To(Equal(true))
			})
			//Invalid case 1
			It("returns error when data is not present in store", func() {
				r1 := store.Rule{
					Id:        "rule1",
					PortRange: []uint16{80, 443},
					RuleMask:  0xff,
					Cidr:      "192.168.ab.cd/24",
					IpSetID:   "ipset1",
				}

				ruleGroup := store.RuleGroup{
					Index:     1,
					Direction: "RX",
					Protocol:  p4.PROTO_TCP,
					Rules:     make(map[string]store.Rule),
				}
				ruleGroup.Rules["rule1"] = r1

				data_invalid := store.Policy{
					Name:       "policy",
					RuleGroups: make(map[uint16]store.RuleGroup),
				}
				data_invalid.RuleGroups[1] = ruleGroup
				ret := data_invalid.DeleteFromStore()
				Expect(ret).To(Equal(false))
			})
		})
	})

	//IpSet: Delete from store
	Describe("DeleteFromStore", func() {

		Context("Deletes IpSet data from the store", func() {

			BeforeEach(func() {
				store.NewPolicy()
				var err error
				tempDir, err = os.MkdirTemp("", "test")
				Expect(err).ShouldNot(HaveOccurred())
				store.StorePath = path.Join(tempDir, "inframanager")
				store.IpsetFile = path.Join(store.StorePath, "ipset_db.json")
			})

			AfterEach(func() {
				_ = os.RemoveAll(tempDir)
			})

			//Valid case 1
			It("Deletes the data from the store and returns true if data is present in the store", func() {
				r1 := store.Rule{
					Id:        "rule1",
					PortRange: []uint16{80, 443},
					RuleMask:  0xff,
					Cidr:      "192.168.1.0/24",
					IpSetID:   "1234",
				}
				ruleGroup := store.RuleGroup{
					Index:     1,
					Direction: "RX",
					Protocol:  p4.PROTO_TCP,
					Rules:     make(map[string]store.Rule),
				}
				ruleGroup.Rules["rule1"] = r1

				data_valid1 := store.Policy{
					Name:       "Policy1",
					RuleGroups: make(map[uint16]store.RuleGroup),
				}
				data_valid1.RuleGroups[1] = ruleGroup
				data_valid1.WriteToStore()

				data_valid := store.IpSet{
					IpsetID:    "1234",
					IpSetIDx:   1,
					PolicyName: "Policy1",
					RuleID:     "RuleID",
					IpAddr:     []string{"10.10.10.1"},
				}
				data_valid.WriteToStore()
				ret := data_valid.DeleteFromStore()
				Expect(ret).To(Equal(true))
			})
			//Invalid case 1
			It("returns error when data is not present in store", func() {
				data_invalid := store.IpSet{
					IpsetID:    "123",
					IpSetIDx:   1,
					PolicyName: "Policy1",
					RuleID:     "RuleID",
					IpAddr:     []string{"10.10.10.1"},
				}
				ret := data_invalid.DeleteFromStore()
				Expect(ret).To(Equal(false))
			})
		})
	})

	//PolicyworkerEndPoint: Delete from store
	Describe("DeleteFromStore", func() {

		Context("Deletes PolicyworkerEndPoint data from the store", func() {

			BeforeEach(func() {
				store.NewPolicy()
				var err error
				tempDir, err = os.MkdirTemp("", "test")
				Expect(err).ShouldNot(HaveOccurred())
				store.StorePath = path.Join(tempDir, "inframanager")
				store.WorkerepFile = path.Join(store.StorePath, "workerep_db.json")
			})

			AfterEach(func() {
				_ = os.RemoveAll(tempDir)
			})

			//Valid case 1
			It("Deletes the data from the store and returns true if data is present in the store", func() {
				data_valid := store.PolicyWorkerEndPoint{
					WorkerEp:          "test-pod",
					WorkerIp:          "10.10.10.1",
					PolicyNameIngress: []string{"policy1", "policy2"},
					PolicyNameEgress:  []string{"policy3", "policy4"},
				}
				data_valid.WriteToStore()
				ret := data_valid.DeleteFromStore()
				Expect(ret).To(Equal(true))
			})
			//Invalid case 1
			It("returns error when data is not present in store", func() {
				data_invalid := store.PolicyWorkerEndPoint{
					WorkerEp:          "test-pod",
					WorkerIp:          "10.10.10.2",
					PolicyNameIngress: []string{"policy1", "policy2"},
					PolicyNameEgress:  []string{"policy3", "policy4"},
				}
				ret := data_invalid.DeleteFromStore()
				Expect(ret).To(Equal(false))
			})
		})
	})

	//Policy: GetFromStore
	Describe("GetFromStore", func() {

		Context("Gets the Policy data from store", func() {

			BeforeEach(func() {
				store.NewPolicy()
				var err error
				tempDir, err = os.MkdirTemp("", "test")
				Expect(err).ShouldNot(HaveOccurred())
				store.StorePath = path.Join(tempDir, "inframanager")
				store.PolicyFile = path.Join(store.StorePath, "policy_db.json")
			})

			AfterEach(func() {
				_ = os.RemoveAll(tempDir)
			})

			//Valid case 1
			It("Gets the data from the store and returns true when data is present", func() {
				r1 := store.Rule{
					Id:        "rule1",
					PortRange: []uint16{80, 443},
					RuleMask:  0xff,
					Cidr:      "192.168.1.0/24",
					IpSetID:   "ipset1",
				}

				ruleGroup := store.RuleGroup{
					Index:     1,
					Direction: "RX",
					Protocol:  p4.PROTO_TCP,
					Rules:     make(map[string]store.Rule),
				}
				ruleGroup.Rules["rule1"] = r1

				data_valid := store.Policy{
					Name:       "policy1",
					RuleGroups: make(map[uint16]store.RuleGroup),
				}
				data_valid.RuleGroups[1] = ruleGroup

				data_valid.WriteToStore()
				ret := data_valid.GetFromStore()
				Expect(ret).To(Equal(data_valid))
			})
			//Invalid case 1
			It("returns nil when data is not present", func() {
				r1 := store.Rule{
					Id:        "rule1",
					PortRange: []uint16{80, 443},
					RuleMask:  0xff,
					Cidr:      "192.168.1.0/24",
					IpSetID:   "ipset1",
				}

				ruleGroup := store.RuleGroup{
					Index:     1,
					Direction: "RX",
					Protocol:  p4.PROTO_TCP,
					Rules:     make(map[string]store.Rule),
				}
				ruleGroup.Rules["rule1"] = r1

				data_invalid1 := store.Policy{
					Name:       "policy",
					RuleGroups: make(map[uint16]store.RuleGroup),
				}
				data_invalid1.RuleGroups[1] = ruleGroup
				ret := data_invalid1.GetFromStore()
				Expect(ret).Should(BeNil())
			})
		})
	})

	//IpSet: GetFromStore
	Describe("GetFromStore", func() {

		Context("Gets the Policy-IpSet data from store", func() {

			BeforeEach(func() {
				store.NewPolicy()
				var err error
				tempDir, err = os.MkdirTemp("", "test")
				Expect(err).ShouldNot(HaveOccurred())
				store.StorePath = path.Join(tempDir, "inframanager")
				store.IpsetFile = path.Join(store.StorePath, "ipset_db.json")
			})

			AfterEach(func() {
				_ = os.RemoveAll(tempDir)
			})

			//Valid case 1
			It("Gets the data from the store and returns true when input is valid", func() {
				data_valid := store.IpSet{
					IpsetID:    "1234",
					IpSetIDx:   1,
					PolicyName: "Policy1",
					RuleID:     "RuleID",
					IpAddr:     []string{"10.10.10.1"},
				}
				data_valid.WriteToStore()
				ret := data_valid.GetFromStore()
				Expect(ret).To(Equal(data_valid))
			})
			//Invalid case 1
			It("returns nil when data is not present", func() {
				data_invalid := store.IpSet{
					IpsetID:    "123",
					IpSetIDx:   1,
					PolicyName: "Policy1",
					RuleID:     "RuleID",
					IpAddr:     []string{"10.10.10.1"},
				}
				ret := data_invalid.GetFromStore()
				Expect(ret).Should(BeNil())
			})
		})
	})

	//WorkerEndPoint: GetFromStore
	Describe("GetFromStore", func() {

		Context("Gets the Policy-WorkerEndPoint data from store", func() {

			BeforeEach(func() {
				store.NewPolicy()
				var err error
				tempDir, err = os.MkdirTemp("", "test")
				Expect(err).ShouldNot(HaveOccurred())
				store.StorePath = path.Join(tempDir, "inframanager")
				store.WorkerepFile = path.Join(store.StorePath, "workerep_db.json")
			})

			AfterEach(func() {
				_ = os.RemoveAll(tempDir)
			})

			// Valid case 1
			It("Gets the data from the store and returns true when input is valid", func() {
				data_valid := store.PolicyWorkerEndPoint{
					WorkerEp:          "test-pod",
					WorkerIp:          "10.10.10.1",
					PolicyNameIngress: []string{"policy1", "policy2"},
					PolicyNameEgress:  []string{"policy3", "policy4"},
				}
				data_valid.WriteToStore()
				ret := data_valid.GetFromStore()
				Expect(ret).To(Equal(data_valid))
			})
			//Invalid case 1
			It("returns nil when data is not present", func() {
				data_invalid := store.PolicyWorkerEndPoint{
					WorkerEp:          "test-pod2",
					WorkerIp:          "10.10.10.2",
					PolicyNameIngress: []string{"policy1", "policy2"},
					PolicyNameEgress:  []string{"policy3", "policy4"},
				}
				ret := data_invalid.GetFromStore()
				Expect(ret).Should(BeNil())
			})
		})
	})

	//Policy: UpdateToStore
	Describe("UpdateToStore", func() {

		Context("updates Policy data to the store", func() {

			BeforeEach(func() {
				store.NewPolicy()
				var err error
				tempDir, err = os.MkdirTemp("", "test")
				Expect(err).ShouldNot(HaveOccurred())
				store.StorePath = path.Join(tempDir, "inframanager")
				store.PolicyFile = path.Join(store.StorePath, "policy_db.json")
			})

			AfterEach(func() {
				_ = os.RemoveAll(tempDir)
			})

			//Valid case 1
			It("returns true if data is valid and update to store succeeds", func() {
				r1 := store.Rule{
					Id:        "rule1",
					PortRange: []uint16{80, 443},
					RuleMask:  0xff,
					Cidr:      "192.168.1.0/24",
					IpSetID:   "ipset1",
				}
				ruleGroup := store.RuleGroup{
					Index:     1,
					Direction: "RX",
					Protocol:  p4.PROTO_TCP,
					Rules:     make(map[string]store.Rule),
				}
				ruleGroup.Rules["rule1"] = r1

				data_valid := store.Policy{
					Name:       "policy1",
					RuleGroups: make(map[uint16]store.RuleGroup),
				}
				data_valid.RuleGroups[1] = ruleGroup
				data_valid.WriteToStore()

				//Updating data
				r2 := store.Rule{
					Id:        "rule1",
					PortRange: []uint16{80, 443},
					RuleMask:  0xff,
					Cidr:      "192.168.1.0/24",
					IpSetID:   "ipset1",
				}
				ruleGroup1 := store.RuleGroup{
					Index:     1,
					Direction: "TX",
					Protocol:  p4.PROTO_UDP,
					Rules:     make(map[string]store.Rule),
				}
				ruleGroup1.Rules["rule1"] = r2

				data_valid1 := store.Policy{
					Name:       "policy1",
					RuleGroups: make(map[uint16]store.RuleGroup),
				}
				data_valid1.RuleGroups[1] = ruleGroup1
				ret := data_valid1.UpdateToStore()
				Expect(ret).To(Equal(true))
			})
			//Valid case 2
			It("returns true if data doesn't exist in store", func() {
				// This case is supposed to pass because if
				// an entry isn't found, it is added instead
				r1 := store.Rule{
					Id:        "rule1",
					PortRange: []uint16{80, 443},
					RuleMask:  0xff,
					Cidr:      "192.168.1.0/24",
					IpSetID:   "ipset1",
				}

				ruleGroup := store.RuleGroup{
					Index:     1,
					Direction: "RX",
					Protocol:  p4.PROTO_TCP,
					Rules:     make(map[string]store.Rule),
				}
				ruleGroup.Rules["rule1"] = r1

				data_valid1 := store.Policy{
					Name:       "policy",
					RuleGroups: make(map[uint16]store.RuleGroup),
				}
				data_valid1.RuleGroups[1] = ruleGroup
				ret := data_valid1.UpdateToStore()
				Expect(ret).To(Equal(true))
			})
			//Valid case 3
			It("returns true if same data already exists in store", func() {
				// The update is an idempotent function
				// and it returns true if the same data exists
				// even though no update is actually done.
				r1 := store.Rule{
					Id:        "rule1",
					PortRange: []uint16{80, 443},
					RuleMask:  0xff,
					Cidr:      "192.168.1.0/24",
					IpSetID:   "ipset1",
				}

				ruleGroup := store.RuleGroup{
					Index:     1,
					Direction: "RX",
					Protocol:  p4.PROTO_TCP,
					Rules:     make(map[string]store.Rule),
				}
				ruleGroup.Rules["rule1"] = r1

				data_valid2 := store.Policy{
					Name:       "policy1",
					RuleGroups: make(map[uint16]store.RuleGroup),
				}
				data_valid2.RuleGroups[1] = ruleGroup
				data_valid2.WriteToStore()
				//Try to update the same data which is already available in store
				ret := data_valid2.UpdateToStore()
				Expect(ret).To(Equal(true))
			})
		})
	})

	//IpSet: UpdateToStore
	Describe("UpdateToStore", func() {

		Context("updates Policy-IpSet data to the store", func() {

			BeforeEach(func() {
				store.NewPolicy()
				var err error
				tempDir, err = os.MkdirTemp("", "test")
				Expect(err).ShouldNot(HaveOccurred())
				store.StorePath = path.Join(tempDir, "inframanager")
				store.IpsetFile = path.Join(store.StorePath, "ipset_db.json")
			})

			AfterEach(func() {
				_ = os.RemoveAll(tempDir)
			})

			//Valid case 1
			It("returns true if data is valid and update to store succeeds", func() {
				data_valid := store.IpSet{
					IpsetID:    "1234",
					IpSetIDx:   1,
					PolicyName: "Policy1",
					RuleID:     "RuleID",
					IpAddr:     []string{"10.10.10.1"},
				}

				data_valid.WriteToStore()
				data_valid.IpAddr = append(data_valid.IpAddr, "10.10.10.2")
				ret := data_valid.UpdateToStore()
				Expect(ret).To(Equal(true))
			})
			//Invalid case 1
			It("returns false if data doesn't exits in store", func() {
				data_valid1 := store.IpSet{
					IpsetID:    "123",
					IpSetIDx:   1,
					PolicyName: "Policy1",
					RuleID:     "RuleID",
					IpAddr:     []string{"10.10.10.1"},
				}
				ret := data_valid1.UpdateToStore()
				Expect(ret).To(Equal(false))
			})
			//Invalid case 2
			It("returns false if Same data exits in store", func() {
				data_valid2 := store.IpSet{
					IpsetID:    "1234",
					IpSetIDx:   1,
					PolicyName: "Policy1",
					RuleID:     "RuleID",
					IpAddr:     []string{"10.10.10.1"},
				}
				data_valid2.WriteToStore()
				//Try to update the same data which is already available in store
				ret := data_valid2.UpdateToStore()
				Expect(ret).To(Equal(false))
			})
		})
	})

	//WorkerIp: UpdateToStore
	Describe("UpdateToStore", func() {

		Context("updates Policy-WorkerEp data to the store", func() {

			BeforeEach(func() {
				store.NewPolicy()
				var err error
				tempDir, err = os.MkdirTemp("", "test")
				Expect(err).ShouldNot(HaveOccurred())
				store.StorePath = path.Join(tempDir, "inframanager")
				store.WorkerepFile = path.Join(store.StorePath, "workerep_db.json")
			})

			AfterEach(func() {
				_ = os.RemoveAll(tempDir)
			})

			//Valid case 1
			It("returns true if data is valid and update to store succeeds", func() {
				data_valid := store.PolicyWorkerEndPoint{
					WorkerEp:          "test-pod",
					WorkerIp:          "10.10.10.1",
					PolicyNameIngress: []string{"policy1", "policy2"},
					PolicyNameEgress:  []string{"policy3", "policy4"},
				}

				data_valid.WriteToStore()
				data_valid.PolicyNameIngress = append(data_valid.PolicyNameIngress, "policy5")
				data_valid.PolicyNameEgress = append(data_valid.PolicyNameEgress, "policy6")
				ret := data_valid.UpdateToStore()
				Expect(ret).To(Equal(true))
			})
			//Valid case 2
			It("returns true if data doesn't exist in store", func() {
				// This case is supposed to pass because if
				// an entry isn't found, it is added instead
				data_valid1 := store.PolicyWorkerEndPoint{
					WorkerEp:          "test-pod",
					WorkerIp:          "10.10.10.2",
					PolicyNameIngress: []string{"policy1", "policy2"},
					PolicyNameEgress:  []string{"policy3", "policy4"},
				}
				ret := data_valid1.UpdateToStore()
				Expect(ret).To(Equal(true))
			})
			//Valid case 3
			It("returns false if same data exists in store", func() {
				// The update is an idempotent function
				// and it returns true if the same data exists
				// even though no update is actually done.
				data_valid2 := store.PolicyWorkerEndPoint{
					WorkerEp:          "test-pod",
					WorkerIp:          "10.10.10.1",
					PolicyNameIngress: []string{"policy1", "policy2"},
					PolicyNameEgress:  []string{"policy3", "policy4"},
				}
				data_valid2.WriteToStore()
				//Try to update the same data to store
				ret := data_valid2.UpdateToStore()
				Expect(ret).To(Equal(true))
			})
		})
	})

	//Polciy: RunSyncPolicyInfo
	Describe("RunSyncPolicyInfo", func() {

		Context("Writes to persistent storage", func() {

			restorewritefile := store.NewWriteFile
			restoremarshalindent := store.JsonMarshalIndent

			BeforeEach(func() {
				store.NewPolicy()
				var err error
				tempDir, err = os.MkdirTemp("", "test")
				Expect(err).ShouldNot(HaveOccurred())
				store.StorePath = path.Join(tempDir, "inframanager")
				store.PolicyFile = path.Join(store.StorePath, "policy_db.json")
				r1 := store.Rule{
					Id:        "rule1",
					PortRange: []uint16{80, 443},
					RuleMask:  0xff,
					Cidr:      "192.168.1.0/24",
					IpSetID:   "ipset1",
				}
				ruleGroup := store.RuleGroup{
					Index:     1,
					Direction: "RX",
					Protocol:  p4.PROTO_TCP,
					Rules:     make(map[string]store.Rule),
				}
				ruleGroup.Rules["rule1"] = r1

				data_valid := store.Policy{
					Name:       "policy1",
					RuleGroups: make(map[uint16]store.RuleGroup),
				}
				data_valid.RuleGroups[1] = ruleGroup
				data_valid.WriteToStore()
				err1 := os.Mkdir(store.StorePath, 0755)
				Expect(err1).ShouldNot(HaveOccurred())
			})

			AfterEach(func() {
				store.NewWriteFile = restorewritefile
				store.JsonMarshalIndent = restoremarshalindent
				_ = os.RemoveAll(tempDir)
			})

			It("returns true", func() {
				ret := store.RunSyncPolicyInfo()
				Expect(ret).To(Equal(true))
			})

			It("returns false if write to file fails", func() {
				store.NewWriteFile = fakewritefile
				ret := store.RunSyncPolicyInfo()
				Expect(ret).To(Equal(false))
			})

			It("returns false if marshal fails", func() {
				store.JsonMarshalIndent = fakemarshal
				ret := store.RunSyncPolicyInfo()
				Expect(ret).To(Equal(false))
			})
		})
	})

	//IpSet: RunSyncIpSetInfo
	Describe("RunSyncIpSetInfo", func() {

		Context("Writes to persistent storage", func() {

			restorewritefile := store.NewWriteFile
			restoremarshalindent := store.JsonMarshalIndent

			BeforeEach(func() {
				store.NewPolicy()
				var err error
				tempDir, err = os.MkdirTemp("", "test")
				Expect(err).ShouldNot(HaveOccurred())
				store.StorePath = path.Join(tempDir, "inframanager")
				store.IpsetFile = path.Join(store.StorePath, "ipset_db.json")
				data_valid := store.IpSet{
					IpsetID:    "1234",
					IpSetIDx:   1,
					PolicyName: "Policy1",
					RuleID:     "RuleID",
					IpAddr:     []string{"10.10.10.1"},
				}
				data_valid.WriteToStore()
				err1 := os.Mkdir(store.StorePath, 0755)
				Expect(err1).ShouldNot(HaveOccurred())
			})

			AfterEach(func() {
				store.NewWriteFile = restorewritefile
				store.JsonMarshalIndent = restoremarshalindent
				_ = os.RemoveAll(tempDir)
			})

			It("returns true", func() {
				ret := store.RunSyncIpSetInfo()
				Expect(ret).To(Equal(true))
			})

			It("returns false if write to file fails", func() {
				store.NewWriteFile = fakewritefile
				ret := store.RunSyncIpSetInfo()
				Expect(ret).To(Equal(false))
			})

			It("returns false if marshal fails", func() {
				store.JsonMarshalIndent = fakemarshal
				ret := store.RunSyncIpSetInfo()
				Expect(ret).To(Equal(false))
			})
		})
	})

	//WorkerIp: RunSyncWorkerEpInfo
	Describe("RunSyncWorkerEpInfo", func() {

		Context("Writes to persistent storage", func() {

			restorewritefile := store.NewWriteFile
			restoremarshalindent := store.JsonMarshalIndent

			BeforeEach(func() {
				store.NewPolicy()
				var err error
				tempDir, err = os.MkdirTemp("", "test")
				Expect(err).ShouldNot(HaveOccurred())
				store.StorePath = path.Join(tempDir, "inframanager")
				store.WorkerepFile = path.Join(store.StorePath, "workerep_db.json")
				data_valid := store.PolicyWorkerEndPoint{
					WorkerEp:          "test-pod",
					WorkerIp:          "10.10.10.1",
					PolicyNameIngress: []string{"policy1", "policy2"},
					PolicyNameEgress:  []string{"policy3", "policy4"},
				}
				data_valid.WriteToStore()
				err1 := os.Mkdir(store.StorePath, 0755)
				Expect(err1).ShouldNot(HaveOccurred())
			})

			AfterEach(func() {
				store.NewWriteFile = restorewritefile
				store.JsonMarshalIndent = restoremarshalindent
				_ = os.RemoveAll(tempDir)
			})

			It("returns true", func() {
				ret := store.RunSyncWorkerEpInfo()
				Expect(ret).To(Equal(true))
			})

			It("returns false if write to file fails", func() {
				store.NewWriteFile = fakewritefile
				ret := store.RunSyncWorkerEpInfo()
				Expect(ret).To(Equal(false))
			})

			It("returns false if marshal fails", func() {
				store.JsonMarshalIndent = fakemarshal
				ret := store.RunSyncWorkerEpInfo()
				Expect(ret).To(Equal(false))
			})
		})
	})
})
