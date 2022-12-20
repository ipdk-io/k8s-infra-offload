package store_test

import (
	"errors"
	"io/fs"
	"os"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/ipdk-io/k8s-infra-offload/pkg/inframanager/store"
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

			AfterEach(func() {
				store.NewOpenFile = restoreopenfile
				store.NewReadFile = restorereadfile
				store.JsonUnmarshal = restorejsonunmarshal
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
				file, _ := restoreopenfile(store.StoreEpFile, os.O_CREATE, 0600)
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

			It("returns error when mac address is invalid", func() {
				data_invalid3 := store.EndPoint{
					PodIpAddress:  "10.10.10.1",
					InterfaceID:   1,
					PodMacAddress: "10.10.10.1",
				}
				ret := data_invalid3.DeleteFromStore()
				Expect(ret).To(Equal(false))
			})

		})

	})

	Describe("GetFromStore", func() {

		Context("Gets the data from store", func() {

			BeforeEach(func() {
				store.NewEndPoint()
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

			It("returns nil when mac address is invalid", func() {
				data_invalid3 := store.EndPoint{
					PodIpAddress:  "10.10.10.1",
					InterfaceID:   1,
					PodMacAddress: "10.10.10.1",
				}
				ret := data_invalid3.GetFromStore()
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
				data_valid := store.EndPoint{
					PodIpAddress:  "10.10.10.4",
					InterfaceID:   4,
					PodMacAddress: "00:00:00:aa:aa:aa",
				}
				data_valid.WriteToStore()
			})

			AfterEach(func() {
				store.NewWriteFile = restorewritefile
				store.JsonMarshalIndent = restoremarshalindent
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

			It("returns true if map is invalid or is empty", func() {
				store.NewService()
				ret := store.IsServiceStoreEmpty()
				Expect(ret).To(Equal(true))
			})

			It("returns false if map is valid and not empty", func() {
				store.NewService()
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

			AfterEach(func() {
				store.NewOpenFile = restoreopenfile
				store.NewReadFile = restorereadfile
				store.JsonUnmarshal = restorejsonunmarshal
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
				store.NewService()
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
				file, _ := restoreopenfile(store.ServicesFile, os.O_CREATE, 0600)
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
			})

			It("returns false if getkey fails", func() {
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
			})

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
			})

			It("returns false if getkey fails", func() {
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
			})

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
			})

			AfterEach(func() {
				store.NewWriteFile = restorewritefile
				store.JsonMarshalIndent = restorejsonmarshalindent
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
