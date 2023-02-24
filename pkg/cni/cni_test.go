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

package cni

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/golang/mock/gomock"
	"github.com/ipdk-io/k8s-infra-offload/pkg/mock_proto"
	"github.com/ipdk-io/k8s-infra-offload/pkg/types"
	"github.com/ipdk-io/k8s-infra-offload/proto"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"gopkg.in/tomb.v2"
)

const (
	bufSize    = 1024 * 1024
	addRequest = `{"interface_name":"eth0","netns":"/var/run/netns/cni-6e82d755-34c1-a423-75db-f9dc757da430","desired_host_interface_name":"caliafb2e1bddef","settings":{"mtu":1500},"container_ips":[{"address":"10.244.0.85/24","gateway":"10.244.0.1"}],"container_routes":["0.0.0.0/0","::/0"],"workload":{"name":"dummynode-k8s-busybox2-eth0","namespace":"default","labels":{"access":"true","app":"sleepy","projectcalico.org/namespace":"default","projectcalico.org/orchestrator":"k8s","projectcalico.org/serviceaccount":"default"},"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"annotations\":{},\"labels\":{\"access\":\"true\",\"app\":\"sleepy\"},\"name\":\"busybox2\",\"namespace\":\"default\"},\"spec\":{\"containers\":[{\"command\":[\"sleep\",\"3600\"],\"image\":\"busybox\",\"name\":\"nwp-busybox2\"}]}}\n"},"endpoint":"eth0","node":"dummynode","orchestrator":"k8s","pod":"busybox2"}}`
	maxPort    = 65535
	minPort    = 52000
)

var (
	mockCrtl       *gomock.Controller
	mockClient     *mock_proto.MockInfraAgentClient
	listener       *bufconn.Listener
	listenFuncBack func(string, string) (net.Listener, error)
	rg             *rand.Rand
)

type podInterfaceMock struct {
	info                   *types.InterfaceInfo
	createPodInterfaceErr  error
	releasePodInterfaceErr error
	addReply               *proto.AddReply
	addReplyErr            error
	delReply               *proto.DelReply
}

func (pi *podInterfaceMock) CreatePodInterface(in *proto.AddRequest) (*types.InterfaceInfo, error) {
	return pi.info, pi.createPodInterfaceErr
}

func (pi *podInterfaceMock) ReleasePodInterface(in *proto.DelRequest) error {
	return pi.releasePodInterfaceErr
}

func (pi *podInterfaceMock) SetupNetwork(context.Context, proto.InfraAgentClient, *types.InterfaceInfo, *proto.AddRequest) (*proto.AddReply, error) {
	return pi.addReply, pi.addReplyErr
}

func (pi *podInterfaceMock) ReleaseNetwork(context.Context, proto.InfraAgentClient, *proto.DelRequest) (*proto.DelReply, error) {
	return pi.delReply, pi.addReplyErr
}

func bufDialer(context.Context, string) (net.Conn, error) {
	return listener.Dial()
}

func mockListen(network, address string) (net.Listener, error) {
	return listener, nil
}

func serve() error {
	return nil
}

func serveErr() error {
	return errors.New("Fake error")
}

func randomPort() string {
	seed := rand.NewSource(time.Now().UnixNano())
	rg = rand.New(seed)
	rPort := rg.Intn(maxPort-minPort) + minPort
	return strconv.Itoa(rPort)
}

type fakeNetNS struct{}

func (fns *fakeNetNS) Do(toRun func(ns.NetNS) error) error {
	return nil
}

func (fns *fakeNetNS) Set() error {
	return nil
}

func (fns *fakeNetNS) Path() string {
	return ""
}

func (fns *fakeNetNS) Fd() uintptr {
	return uintptr(0)
}

func (fns *fakeNetNS) Close() error {
	return nil
}

func fakeGetCredential() (credentials.TransportCredentials, error) {
	return insecure.NewCredentials(), nil
}

func TestCni(t *testing.T) {
	mockCrtl = gomock.NewController(t)
	mockClient = mock_proto.NewMockInfraAgentClient(mockCrtl)
	RegisterFailHandler(Fail)
	RunSpecs(t, "CNI backend Test Suite")
}

var _ = Describe("CNI backend server", func() {
	var _ = BeforeSuite(func() {
		listener = bufconn.Listen(bufSize)
		newInfraAgentClient = func(cc *grpc.ClientConn) proto.InfraAgentClient {
			return mockClient
		}
	})

	var _ = AfterSuite(func() {
		mockCrtl.Finish()
		listener.Close()
	})

	var _ = BeforeEach(func() {
		getCredentialFunc = fakeGetCredential
		grpcDial = func(target string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
			return grpc.DialContext(context.TODO(), "bufnet", grpc.WithContextDialer(bufDialer), grpc.WithTransportCredentials(insecure.NewCredentials()))
		}
	})

	var _ = Context("Add() should", func() {
		var _ = Context("return no error", func() {
			var _ = It("when PodInterface is able to configure network", func() {
				in := &proto.AddRequest{}
				err := json.Unmarshal([]byte(addRequest), in)
				Expect(err).ToNot(HaveOccurred())
				newInfraAgentClient = func(cc *grpc.ClientConn) proto.InfraAgentClient {
					return mockClient
				}
				server := &CniServer{
					podInterfaceType: "dummy",
					podInterface: &podInterfaceMock{
						info: &types.InterfaceInfo{
							PciAddr:       "0000:0e:00.0",
							InterfaceName: "eth0",
							VfID:          1,
							MacAddr:       "FF:FF:FF:FF:FF:FF",
						},
						createPodInterfaceErr:  nil,
						releasePodInterfaceErr: nil,
						addReply: &proto.AddReply{
							Successful: true,
						},
						addReplyErr: nil,
						delReply:    &proto.DelReply{Successful: true},
					},
					log: logrus.NewEntry(logrus.New()),
				}
				out, err := server.Add(context.TODO(), in)
				Expect(err).ToNot(HaveOccurred())
				Expect(out.Successful).To(BeTrue())
			})
		})

		var _ = Context("return error", func() {
			in := &proto.AddRequest{}
			err := json.Unmarshal([]byte(addRequest), in)
			Expect(err).ToNot(HaveOccurred())
			var _ = It("when CreatePodInterface fails", func() {
				server := &CniServer{
					podInterfaceType: "dummy",
					podInterface: &podInterfaceMock{
						info: &types.InterfaceInfo{
							PciAddr:       "0000:0e:00.0",
							InterfaceName: "eth0",
							VfID:          1,
							MacAddr:       "FF:FF:FF:FF:FF:FF",
						},
						createPodInterfaceErr:  fmt.Errorf("dummy error"),
						releasePodInterfaceErr: nil,
						addReply: &proto.AddReply{
							Successful: false,
						},
						addReplyErr: fmt.Errorf("dummy error"),
						delReply:    &proto.DelReply{Successful: true},
					},
					log: logrus.NewEntry(logrus.New()),
				}
				out, err := server.Add(context.TODO(), in)
				Expect(err).ToNot(HaveOccurred())
				Expect(out).ToNot(BeNil())
				Expect(out.Successful).To(BeFalse())
				Expect(out.ErrorMessage).ToNot(BeEmpty())
			})
			var _ = It("when SetupeNetwork fails", func() {
				server := &CniServer{
					podInterfaceType: "dummy",
					podInterface: &podInterfaceMock{
						info: &types.InterfaceInfo{
							PciAddr:       "0000:0e:00.0",
							InterfaceName: "eth0",
							VfID:          1,
							MacAddr:       "FF:FF:FF:FF:FF:FF",
						},
						createPodInterfaceErr:  nil,
						releasePodInterfaceErr: nil,

						addReply: &proto.AddReply{
							Successful:   false,
							ErrorMessage: "dummy error",
						},
						addReplyErr: fmt.Errorf("dummy error"),
						delReply:    &proto.DelReply{Successful: true},
					},
					log: logrus.NewEntry(logrus.New()),
				}
				out, err := server.Add(context.TODO(), in)
				Expect(err).To(HaveOccurred())
				Expect(out).ToNot(BeNil())
				Expect(out.Successful).To(BeFalse())
				Expect(out.ErrorMessage).ToNot(BeEmpty())
			})
			var _ = It("when dial to infra manager fails", func() {
				server := &CniServer{
					podInterfaceType: "dummy",
					podInterface: &podInterfaceMock{
						info: &types.InterfaceInfo{
							PciAddr:       "0000:0e:00.0",
							InterfaceName: "eth0",
							VfID:          1,
							MacAddr:       "FF:FF:FF:FF:FF:FF",
						},
						createPodInterfaceErr:  nil,
						releasePodInterfaceErr: nil,
						addReply: &proto.AddReply{
							Successful: true,
						},
						addReplyErr: nil,
						delReply:    &proto.DelReply{Successful: true},
					},
					log: logrus.NewEntry(logrus.New()),
				}
				grpcDial = func(target string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
					return nil, fmt.Errorf("dummy error")
				}
				out, err := server.Add(context.TODO(), in)
				Expect(err).ToNot(HaveOccurred())
				Expect(out.Successful).To(BeFalse())
				Expect(out.ErrorMessage).ToNot(BeEmpty())
			})
		})
	})

	var _ = Context("Del() should", func() {
		var _ = Context("return no error", func() {
			var _ = It("when PodInterface is able to delete interface", func() {
				in := &proto.DelRequest{
					InterfaceName: "eth0",
					Netns:         "dummy-net-ns",
				}
				server := &CniServer{
					podInterfaceType: "dummy",
					podInterface: &podInterfaceMock{
						info: &types.InterfaceInfo{
							PciAddr:       "0000:0e:00.0",
							InterfaceName: "eth0",
							VfID:          1,
							MacAddr:       "FF:FF:FF:FF:FF:FF",
						},
						createPodInterfaceErr:  nil,
						releasePodInterfaceErr: nil,
						addReply: &proto.AddReply{
							Successful: true,
						},
						addReplyErr: nil,
						delReply:    &proto.DelReply{Successful: true},
					},
					log: logrus.NewEntry(logrus.New()),
				}
				out, err := server.Del(context.TODO(), in)
				Expect(err).ToNot(HaveOccurred())
				Expect(out.Successful).To(BeTrue())
			})
			var _ = It("when namespace does not exist", func() {
				in := &proto.DelRequest{
					InterfaceName: "eth0",
					Netns:         "dummy-net-ns",
				}
				server := &CniServer{
					podInterfaceType: "dummy",
					podInterface: &podInterfaceMock{
						info: &types.InterfaceInfo{
							PciAddr:       "0000:0e:00.0",
							InterfaceName: "eth0",
							VfID:          1,
							MacAddr:       "FF:FF:FF:FF:FF:FF",
						},
						createPodInterfaceErr:  nil,
						releasePodInterfaceErr: nil,
						addReply: &proto.AddReply{
							Successful: true,
						},
						addReplyErr: nil,
						delReply:    &proto.DelReply{Successful: true},
					},
					log: logrus.NewEntry(logrus.New()),
				}
				getNSFunc = func(nspath string) (ns.NetNS, error) {
					return nil, errors.New("Namespace does not exist")
				}
				out, err := server.Del(context.TODO(), in)
				Expect(err).ToNot(HaveOccurred())
				Expect(out.Successful).To(BeTrue())
			})
		})
		var _ = Context("return error", func() {
			in := &proto.DelRequest{
				InterfaceName: "eth0",
				Netns:         "dummy-net-ns",
			}
			var _ = It("when dial to infra manager fails", func() {
				server := &CniServer{
					podInterfaceType: "dummy",
					podInterface: &podInterfaceMock{
						info: &types.InterfaceInfo{
							PciAddr:       "0000:0e:00.0",
							InterfaceName: "eth0",
							VfID:          1,
							MacAddr:       "FF:FF:FF:FF:FF:FF",
						},
						createPodInterfaceErr:  nil,
						releasePodInterfaceErr: nil,
						addReply: &proto.AddReply{
							Successful: true,
						},
						addReplyErr: nil,
						delReply:    &proto.DelReply{Successful: false},
					},
					log: logrus.NewEntry(logrus.New()),
				}
				grpcDial = func(target string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
					return nil, fmt.Errorf("dummy error")
				}
				getNSFunc = func(nspath string) (ns.NetNS, error) {
					return &fakeNetNS{}, nil
				}
				out, err := server.Del(context.TODO(), in)
				Expect(err).ToNot(HaveOccurred())
				Expect(out.Successful).To(BeFalse())
				Expect(out.ErrorMessage).ToNot(BeEmpty())
			})

			var _ = It("when PodInterface fails to do request", func() {
				server := &CniServer{
					podInterfaceType: "dummy",
					podInterface: &podInterfaceMock{
						info: &types.InterfaceInfo{
							PciAddr:       "0000:0e:00.0",
							InterfaceName: "eth0",
							VfID:          1,
							MacAddr:       "FF:FF:FF:FF:FF:FF",
						},
						createPodInterfaceErr:  nil,
						releasePodInterfaceErr: nil,
						addReply: &proto.AddReply{
							Successful: true,
						},
						addReplyErr: fmt.Errorf("dummy error"),
						delReply: &proto.DelReply{
							Successful:   false,
							ErrorMessage: "dummy error",
						},
					},
					log: logrus.NewEntry(logrus.New()),
				}

				out, err := server.Del(context.TODO(), in)
				Expect(err).To(HaveOccurred())
				Expect(out.Successful).To(BeFalse())
				Expect(out.ErrorMessage).ToNot(BeEmpty())
			})

			var _ = It("when PodInterface failes to RelasesPodInterface", func() {
				server := &CniServer{
					podInterfaceType: "dummy",
					podInterface: &podInterfaceMock{
						info: &types.InterfaceInfo{
							PciAddr:       "0000:0e:00.0",
							InterfaceName: "eth0",
							VfID:          1,
							MacAddr:       "FF:FF:FF:FF:FF:FF",
						},
						createPodInterfaceErr:  nil,
						releasePodInterfaceErr: fmt.Errorf("dummy error"),
						addReply: &proto.AddReply{
							Successful: true,
						},
						addReplyErr: nil,
						delReply: &proto.DelReply{
							Successful:   false,
							ErrorMessage: "dummy error",
						},
					},
					log: logrus.NewEntry(logrus.New()),
				}
				out, err := server.Del(context.TODO(), in)
				Expect(err).ToNot(HaveOccurred())
				Expect(out.Successful).To(BeFalse())
				Expect(out.ErrorMessage).ToNot(BeEmpty())
			})
		})
	})

	var _ = Context("Creation and deletion of the server should return no error when", func() {
		var _ = It("NewCniServer, GetName, and StopServer are called", func() {
			listenFuncBack = listenFunc
			listenFunc = mockListen
			agentAddr := fmt.Sprintf("%s:%s", types.InfraAgentAddr, randomPort())
			server, err := NewCniServer(logrus.New().WithContext(context.TODO()), "dummy", agentAddr, nil)
			Expect(err).ToNot(HaveOccurred())
			name := server.GetName()
			Expect(name).To(Equal("cni-server"))
			go func() {
				defer GinkgoRecover()
				_ = server.(*CniServer).serve()
			}()
			server.StopServer()
			listenFunc = listenFuncBack
		})
	})

	var _ = Context("Creation and deletion of the server should return error when", func() {
		var _ = It("cannot bind to URI", func() {
			_, err := NewCniServer(logrus.New().WithContext(context.TODO()), "dummy", "0.0.0.0:-1", nil)
			Expect(err).To(HaveOccurred())
		})
		var _ = It("cannot create interface", func() {
			agentAddr := fmt.Sprintf("%s:%s", types.InfraAgentAddr, randomPort())
			newPodInterfaceBackup := newPodInterface
			newPodInterface = func(t string, log *logrus.Entry) (types.PodInterface, error) { return nil, errors.New("Fake error") }
			_, err := NewCniServer(logrus.New().WithContext(context.TODO()), "unupportedType", agentAddr, nil)
			Expect(err).To(HaveOccurred())
			// s.StopServer()
			newPodInterface = newPodInterfaceBackup
		})
	})

	var _ = Context("CniServer Start() should", func() {
		var _ = It("return no error", func() {
			agentAddr := fmt.Sprintf("%s:%s", types.InfraAgentAddr, randomPort())
			server, err := NewCniServer(logrus.New().WithContext(context.TODO()), "dummy", agentAddr, serve)
			Expect(err).ToNot(HaveOccurred())
			t := &tomb.Tomb{}
			go func() {
				err = server.Start(t)
			}()
			t.Kill(errors.New(""))
			Expect(err).ToNot(HaveOccurred())
		})

		var _ = It("return error", func() {
			agentAddr := fmt.Sprintf("%s:%s", types.InfraAgentAddr, randomPort())
			server, err := NewCniServer(logrus.New().WithContext(context.TODO()), "dummy", agentAddr, serveErr)
			Expect(err).ToNot(HaveOccurred())
			t := &tomb.Tomb{}
			err = server.Start(t)
			Expect(err).To(HaveOccurred())
		})
	})

	var _ = Context("CniServer Watch() should", func() {
		var _ = It("return an error", func() {
			agentAddr := fmt.Sprintf("%s:%s", types.InfraAgentAddr, randomPort())
			server, err := NewCniServer(logrus.New().WithContext(context.TODO()), "dummy", agentAddr, serve)
			Expect(err).ToNot(HaveOccurred())
			srv, ok := server.(*CniServer)
			Expect(ok).To(BeTrue())
			err = srv.Watch(nil, nil)
			Expect(err).To(HaveOccurred())
		})
	})

	var _ = Context("CniServer Check() should", func() {
		var _ = It("return no error", func() {
			agentAddr := fmt.Sprintf("%s:%s", types.InfraAgentAddr, randomPort())
			server, err := NewCniServer(logrus.New().WithContext(context.TODO()), "dummy", agentAddr, serve)
			Expect(err).ToNot(HaveOccurred())
			srv, ok := server.(*CniServer)
			Expect(ok).To(BeTrue())
			types.CNIServerStatus = types.ServerStatusOK
			_, err = srv.Check(context.TODO(), nil)
			Expect(err).ToNot(HaveOccurred())
		})
		var _ = It("return an error", func() {
			agentAddr := fmt.Sprintf("%s:%s", types.InfraAgentAddr, randomPort())
			server, err := NewCniServer(logrus.New().WithContext(context.TODO()), "dummy", agentAddr, serve)
			Expect(err).ToNot(HaveOccurred())
			srv, ok := server.(*CniServer)
			Expect(ok).To(BeTrue())
			types.CNIServerStatus = types.ServerStatusStopped
			_, err = srv.Check(context.TODO(), nil)
			Expect(err).To(HaveOccurred())
		})
	})
})
