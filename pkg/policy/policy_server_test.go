package policy

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/ipdk-io/k8s-infra-offload/pkg/mock_proto"
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

const bufSize = 1024 * 1024

var (
	mockCrtl       *gomock.Controller
	mockClient     *mock_proto.MockInfraAgentClient
	grpcListener   *bufconn.Listener
	socketListener *bufconn.Listener
	ts             *testing.T
)

func TestPolicyServer(t *testing.T) {
	ts = t
	RegisterFailHandler(Fail)
	RunSpecs(t, "Policy Server Test Suite")
}

func wrapPayloadWithEnvelope(msg interface{}, seqNo uint64) (*proto.ToDataplane, error) {
	// Wrap the payload message in an envelope so that protobuf takes care of deserialising
	// it as the correct type.
	envelope := &proto.ToDataplane{
		SequenceNumber: seqNo,
	}
	switch msg := msg.(type) {
	case *proto.ConfigUpdate:
		envelope.Payload = &proto.ToDataplane_ConfigUpdate{ConfigUpdate: msg}
	case *proto.InSync:
		envelope.Payload = &proto.ToDataplane_InSync{InSync: msg}
	case *proto.IPSetUpdate:
		envelope.Payload = &proto.ToDataplane_IpsetUpdate{IpsetUpdate: msg}
	case *proto.IPSetDeltaUpdate:
		envelope.Payload = &proto.ToDataplane_IpsetDeltaUpdate{IpsetDeltaUpdate: msg}
	case *proto.IPSetRemove:
		envelope.Payload = &proto.ToDataplane_IpsetRemove{IpsetRemove: msg}
	case *proto.ActivePolicyUpdate:
		envelope.Payload = &proto.ToDataplane_ActivePolicyUpdate{ActivePolicyUpdate: msg}
	case *proto.ActivePolicyRemove:
		envelope.Payload = &proto.ToDataplane_ActivePolicyRemove{ActivePolicyRemove: msg}
	case *proto.ActiveProfileUpdate:
		envelope.Payload = &proto.ToDataplane_ActiveProfileUpdate{ActiveProfileUpdate: msg}
	case *proto.ActiveProfileRemove:
		envelope.Payload = &proto.ToDataplane_ActiveProfileRemove{ActiveProfileRemove: msg}
	case *proto.HostEndpointUpdate:
		envelope.Payload = &proto.ToDataplane_HostEndpointUpdate{HostEndpointUpdate: msg}
	case *proto.HostEndpointRemove:
		envelope.Payload = &proto.ToDataplane_HostEndpointRemove{HostEndpointRemove: msg}
	case *proto.WorkloadEndpointUpdate:
		envelope.Payload = &proto.ToDataplane_WorkloadEndpointUpdate{WorkloadEndpointUpdate: msg}
	case *proto.WorkloadEndpointRemove:
		envelope.Payload = &proto.ToDataplane_WorkloadEndpointRemove{WorkloadEndpointRemove: msg}
	case *proto.HostMetadataUpdate:
		envelope.Payload = &proto.ToDataplane_HostMetadataUpdate{HostMetadataUpdate: msg}
	case *proto.HostMetadataRemove:
		envelope.Payload = &proto.ToDataplane_HostMetadataRemove{HostMetadataRemove: msg}
	case *proto.IPAMPoolUpdate:
		envelope.Payload = &proto.ToDataplane_IpamPoolUpdate{IpamPoolUpdate: msg}
	case *proto.IPAMPoolRemove:
		envelope.Payload = &proto.ToDataplane_IpamPoolRemove{IpamPoolRemove: msg}
	case *proto.ServiceAccountUpdate:
		envelope.Payload = &proto.ToDataplane_ServiceAccountUpdate{ServiceAccountUpdate: msg}
	case *proto.ServiceAccountRemove:
		envelope.Payload = &proto.ToDataplane_ServiceAccountRemove{ServiceAccountRemove: msg}
	case *proto.NamespaceUpdate:
		envelope.Payload = &proto.ToDataplane_NamespaceUpdate{NamespaceUpdate: msg}
	case *proto.NamespaceRemove:
		envelope.Payload = &proto.ToDataplane_NamespaceRemove{NamespaceRemove: msg}
	case *proto.RouteUpdate:
		envelope.Payload = &proto.ToDataplane_RouteUpdate{RouteUpdate: msg}
	case *proto.RouteRemove:
		envelope.Payload = &proto.ToDataplane_RouteRemove{RouteRemove: msg}
	case *proto.VXLANTunnelEndpointUpdate:
		envelope.Payload = &proto.ToDataplane_VtepUpdate{VtepUpdate: msg}
	case *proto.VXLANTunnelEndpointRemove:
		envelope.Payload = &proto.ToDataplane_VtepRemove{VtepRemove: msg}
	case *proto.WireguardEndpointUpdate:
		envelope.Payload = &proto.ToDataplane_WireguardEndpointUpdate{WireguardEndpointUpdate: msg}
	case *proto.WireguardEndpointRemove:
		envelope.Payload = &proto.ToDataplane_WireguardEndpointRemove{WireguardEndpointRemove: msg}
	case *proto.GlobalBGPConfigUpdate:
		envelope.Payload = &proto.ToDataplane_GlobalBgpConfigUpdate{GlobalBgpConfigUpdate: msg}

	default:
		return nil, fmt.Errorf("Unknown message type: %T", msg)
	}

	return envelope, nil
}

func writeTo(conn net.Conn, data []byte) error {
	lengthBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(lengthBytes, uint64(len(data)))
	var messageBuf bytes.Buffer
	messageBuf.Write(lengthBytes)
	messageBuf.Write(data)
	for {
		_, err := messageBuf.WriteTo(conn)
		if err == io.ErrShortWrite {
			continue
		}
		if err != nil {
			return err
		}
		break
	}
	return nil
}

func testSendMessage(msg interface{}) {
	var t tomb.Tomb
	srv, err := NewPolicyServer(logrus.NewEntry(logrus.StandardLogger()))
	Expect(err).ToNot(HaveOccurred())
	Expect(srv).NotTo(BeNil())
	t.Go(func() error {
		defer GinkgoRecover()
		// do not call Start fake accept
		srvConn, err := socketListener.Accept()
		if err != nil {
			// unexpected
			return err
		}
		go func() {
			defer GinkgoRecover()
			bs, err := io.ReadAll(srvConn)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(bs).NotTo(BeEmpty())
		}()
		<-t.Dying()
		return nil
	})
	conn, err := socketListener.Dial()
	Expect(err).ShouldNot(HaveOccurred())
	err = srv.(*PolicyServer).SendMessage(conn, msg)
	Expect(err).ToNot(HaveOccurred())
	t.Kill(errors.New("stop"))
	err = t.Wait()
	Expect(err.Error()).To(Equal("stop"))
	err = conn.Close()
	Expect(err).ToNot(HaveOccurred())
}

func bufDialer(context.Context, string) (net.Conn, error) {
	return grpcListener.Dial()
}

var _ = BeforeSuite(func() {
	pbNewInfraAgentClient = func(cc *grpc.ClientConn) proto.InfraAgentClient {
		return mockClient
	}

	grpcDial = func(target string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
		cc := &grpc.ClientConn{}
		return cc, nil
	}
	getCredentialFunc = fakeGetCredential

	cancellableListener = func(ctx context.Context) (net.Listener, error) {
		return socketListener, nil
	}

	removeSocket = func(path string) error {
		return nil
	}
})

func fakeGetCredential() (credentials.TransportCredentials, error) {
	return insecure.NewCredentials(), nil
}

func testPolicyMsg(bs []byte, callExpect *gomock.Call) {
	var t tomb.Tomb

	done := false

	callExpect.DoAndReturn(func(_ interface{}, _ interface{}, _ ...interface{}) (*proto.Reply, error) {
		done = true
		return &proto.Reply{Successful: true}, nil
	})

	srv, err := NewPolicyServer(logrus.NewEntry(logrus.StandardLogger()))
	Expect(err).ToNot(HaveOccurred())
	Expect(srv).NotTo(BeNil())
	t.Go(func() error {
		defer GinkgoRecover()
		if err := srv.Start(&t); err != nil {
			return err
		}
		return nil
	})

	conn, err := socketListener.Dial()
	Expect(err).ShouldNot(HaveOccurred())

	err = writeTo(conn, bs)
	Expect(err).ShouldNot(HaveOccurred())

	Eventually(func() bool {
		return done
	}, "3s").Should(Equal(true))

	t.Kill(errors.New("stop"))
	err = t.Wait()
	Expect(err).To(HaveOccurred())
	Expect(err.Error()).Should(Equal("stop"))
}

var _ = Describe("policy", func() {
	var _ = BeforeEach(func() {
		grpcListener = bufconn.Listen(bufSize)
		socketListener = bufconn.Listen(bufSize)
		mockCrtl = gomock.NewController(ts)
		mockClient = mock_proto.NewMockInfraAgentClient(mockCrtl)
	})

	var _ = AfterEach(func() {
		grpcListener.Close()
		grpcListener = nil
		socketListener.Close()
		socketListener = nil
		mockClient = nil
		mockCrtl.Finish()
	})

	var _ = Context("SyncPolicy() should", func() {
		var _ = It("return no error when handling IPSetUpdate", func() {
			msg := &proto.IPSetUpdate{Id: "dummyId", Members: []string{"1.2.3.4/32"}, Type: proto.IPSetUpdate_NET}

			envelope, err := wrapPayloadWithEnvelope(msg, 0)
			Expect(err).ShouldNot(HaveOccurred())

			bs, err := envelope.Marshal()
			Expect(err).ShouldNot(HaveOccurred())
			call := mockClient.EXPECT().UpdateIPSet(gomock.Any(), gomock.Any()).Times(1)
			testPolicyMsg(bs, call)
		})

		var _ = It("return no error when handling IPSetRemove", func() {
			msg := &proto.IPSetRemove{Id: "dummyId"}
			envelope, err := wrapPayloadWithEnvelope(msg, 0)
			Expect(err).ShouldNot(HaveOccurred())
			bs, err := envelope.Marshal()
			Expect(err).ShouldNot(HaveOccurred())
			call := mockClient.EXPECT().RemoveIPSet(gomock.Any(), gomock.Any()).Times(1)
			testPolicyMsg(bs, call)
		})

		var _ = It("return no error when handling IPSetDeltaUpdate", func() {
			msg := &proto.IPSetDeltaUpdate{Id: "dummyId", AddedMembers: []string{"1.1.1.1"}, RemovedMembers: []string{"2.2.2.2"}}
			envelope, err := wrapPayloadWithEnvelope(msg, 0)
			Expect(err).ShouldNot(HaveOccurred())
			bs, err := envelope.Marshal()
			Expect(err).ShouldNot(HaveOccurred())
			call := mockClient.EXPECT().UpdateIPSetDelta(gomock.Any(), gomock.Any()).Times(1)
			testPolicyMsg(bs, call)

		})

		var _ = It("return no error when handling ActivePolicyUpdate", func() {
			in := proto.Rule{Action: "dummy", SrcIpSetIds: []string{"dummmyId"}}
			msg := &proto.ActivePolicyUpdate{Id: &proto.PolicyID{}, Policy: &proto.Policy{Namespace: "dummy", InboundRules: []*proto.Rule{&in}, OutboundRules: []*proto.Rule{}}}
			envelope, err := wrapPayloadWithEnvelope(msg, 0)
			Expect(err).ShouldNot(HaveOccurred())
			bs, err := envelope.Marshal()
			Expect(err).ShouldNot(HaveOccurred())
			call := mockClient.EXPECT().ActivePolicyUpdate(gomock.Any(), gomock.Any()).Times(1)
			testPolicyMsg(bs, call)
		})

		var _ = It("return no error when handling ActivePolicyRemove", func() {
			msg := &proto.ActivePolicyRemove{Id: &proto.PolicyID{Tier: "dummy", Name: "dummy"}}
			envelope, err := wrapPayloadWithEnvelope(msg, 0)
			Expect(err).ShouldNot(HaveOccurred())
			bs, err := envelope.Marshal()
			Expect(err).ShouldNot(HaveOccurred())
			call := mockClient.EXPECT().ActivePolicyRemove(gomock.Any(), gomock.Any()).Times(1)
			testPolicyMsg(bs, call)
		})

		var _ = It("return no error when handling ActiveProfileUpdate", func() {
			in := proto.Rule{Action: "dummy", SrcIpSetIds: []string{"dummmyId"}}
			msg := &proto.ActiveProfileUpdate{Id: &proto.ProfileID{Name: "dummy"}, Profile: &proto.Profile{InboundRules: []*proto.Rule{&in}, OutboundRules: []*proto.Rule{}}}
			envelope, err := wrapPayloadWithEnvelope(msg, 0)
			Expect(err).ShouldNot(HaveOccurred())
			bs, err := envelope.Marshal()
			Expect(err).ShouldNot(HaveOccurred())
			call := mockClient.EXPECT().UpdateActiveProfile(gomock.Any(), gomock.Any()).Times(1)
			testPolicyMsg(bs, call)
		})

		var _ = It("return no error when handling ActiveProfileRemove", func() {
			msg := &proto.ActiveProfileRemove{Id: &proto.ProfileID{Name: "dummy"}}
			envelope, err := wrapPayloadWithEnvelope(msg, 0)
			Expect(err).ShouldNot(HaveOccurred())
			bs, err := envelope.Marshal()
			Expect(err).ShouldNot(HaveOccurred())
			call := mockClient.EXPECT().RemoveActiveProfile(gomock.Any(), gomock.Any()).Times(1)
			testPolicyMsg(bs, call)
		})

		var _ = It("return no error when handling HostEndpointUpdate", func() {
			msg := &proto.HostEndpointUpdate{Id: &proto.HostEndpointID{EndpointId: "dummy"}, Endpoint: &proto.HostEndpoint{Name: "dummy"}}
			envelope, err := wrapPayloadWithEnvelope(msg, 0)
			Expect(err).ShouldNot(HaveOccurred())
			bs, err := envelope.Marshal()
			Expect(err).ShouldNot(HaveOccurred())
			call := mockClient.EXPECT().UpdateHostEndpoint(gomock.Any(), gomock.Any()).Times(1)
			testPolicyMsg(bs, call)
		})

		var _ = It("return no error when handling HostEndpointRemove", func() {
			msg := &proto.HostEndpointRemove{Id: &proto.HostEndpointID{EndpointId: "dummy"}}
			envelope, err := wrapPayloadWithEnvelope(msg, 0)
			Expect(err).ShouldNot(HaveOccurred())
			bs, err := envelope.Marshal()
			Expect(err).ShouldNot(HaveOccurred())
			call := mockClient.EXPECT().RemoveHostEndpoint(gomock.Any(), gomock.Any()).Times(1)
			testPolicyMsg(bs, call)
		})

		var _ = It("return no error when handling WorkloadEndpointUpdate", func() {
			msg := &proto.WorkloadEndpointUpdate{Id: &proto.WorkloadEndpointID{WorkloadId: "dummy", OrchestratorId: "k8s", EndpointId: "dummy"}, Endpoint: &proto.WorkloadEndpoint{Name: "dummy"}}
			envelope, err := wrapPayloadWithEnvelope(msg, 0)
			Expect(err).ShouldNot(HaveOccurred())
			bs, err := envelope.Marshal()
			Expect(err).ShouldNot(HaveOccurred())
			call := mockClient.EXPECT().UpdateLocalEndpoint(gomock.Any(), gomock.Any()).Times(1)
			testPolicyMsg(bs, call)
		})

		var _ = It("return no error when handling WorloadEndpointRemove", func() {
			msg := &proto.WorkloadEndpointRemove{Id: &proto.WorkloadEndpointID{OrchestratorId: "k8s", WorkloadId: "dummy", EndpointId: "dummy"}}
			envelope, err := wrapPayloadWithEnvelope(msg, 0)
			Expect(err).ShouldNot(HaveOccurred())
			bs, err := envelope.Marshal()
			Expect(err).ShouldNot(HaveOccurred())
			call := mockClient.EXPECT().RemoveLocalEndpoint(gomock.Any(), gomock.Any()).Times(1)
			testPolicyMsg(bs, call)
		})

		var _ = It("return no error when handling HostMetadataUpdate", func() {
			msg := &proto.HostMetadataUpdate{Hostname: "dummy", Ipv4Addr: "1.1.1.1"}
			envelope, err := wrapPayloadWithEnvelope(msg, 0)
			Expect(err).ShouldNot(HaveOccurred())
			bs, err := envelope.Marshal()
			Expect(err).ShouldNot(HaveOccurred())
			call := mockClient.EXPECT().UpdateHostMetaData(gomock.Any(), gomock.Any()).Times(1)
			testPolicyMsg(bs, call)
		})

		var _ = It("return no error when handling HostMetadataRemove", func() {
			msg := &proto.HostMetadataRemove{Hostname: "dummy", Ipv4Addr: "2.2.2.2"}
			envelope, err := wrapPayloadWithEnvelope(msg, 0)
			Expect(err).ShouldNot(HaveOccurred())
			bs, err := envelope.Marshal()
			Expect(err).ShouldNot(HaveOccurred())
			call := mockClient.EXPECT().RemoveHostMetaData(gomock.Any(), gomock.Any()).Times(1)
			testPolicyMsg(bs, call)
		})

		var _ = It("return no error when handling ServiceAccountUpdate", func() {
			msg := &proto.ServiceAccountUpdate{Id: &proto.ServiceAccountID{Namespace: "dummy", Name: "dummy"}, Labels: make(map[string]string)}
			envelope, err := wrapPayloadWithEnvelope(msg, 0)
			Expect(err).ShouldNot(HaveOccurred())
			bs, err := envelope.Marshal()
			Expect(err).ShouldNot(HaveOccurred())
			call := mockClient.EXPECT().UpdateServiceAccount(gomock.Any(), gomock.Any()).Times(1)
			testPolicyMsg(bs, call)
		})

		var _ = It("return no error when handling ServiceAccountRemove", func() {
			msg := &proto.ServiceAccountRemove{Id: &proto.ServiceAccountID{Namespace: "dummy", Name: "dummy"}}
			envelope, err := wrapPayloadWithEnvelope(msg, 0)
			Expect(err).ShouldNot(HaveOccurred())
			bs, err := envelope.Marshal()
			Expect(err).ShouldNot(HaveOccurred())
			call := mockClient.EXPECT().RemoveServiceAccount(gomock.Any(), gomock.Any()).Times(1)
			testPolicyMsg(bs, call)
		})

		var _ = It("return no error when handling NamespaceUpdate", func() {
			msg := &proto.NamespaceUpdate{Id: &proto.NamespaceID{Name: "dummy"}, Labels: make(map[string]string)}
			envelope, err := wrapPayloadWithEnvelope(msg, 0)
			Expect(err).ShouldNot(HaveOccurred())
			bs, err := envelope.Marshal()
			Expect(err).ShouldNot(HaveOccurred())
			call := mockClient.EXPECT().UpdateNamespace(gomock.Any(), gomock.Any()).Times(1)
			testPolicyMsg(bs, call)
		})

		var _ = It("return no error when handling NamespaceRemove", func() {
			msg := &proto.NamespaceRemove{Id: &proto.NamespaceID{Name: "dummy"}}
			envelope, err := wrapPayloadWithEnvelope(msg, 0)
			Expect(err).ShouldNot(HaveOccurred())
			bs, err := envelope.Marshal()
			Expect(err).ShouldNot(HaveOccurred())
			call := mockClient.EXPECT().RemoveNamespace(gomock.Any(), gomock.Any()).Times(1)
			testPolicyMsg(bs, call)
		})

		var _ = It("return no error when handling RouteUpdate", func() {
			msg := &proto.RouteUpdate{Type: proto.RouteType_LOCAL_HOST, DstNodeName: "dummmy", NatOutgoing: false, Dst: "2.2.2.2"}
			envelope, err := wrapPayloadWithEnvelope(msg, 0)
			Expect(err).ShouldNot(HaveOccurred())
			bs, err := envelope.Marshal()
			Expect(err).ShouldNot(HaveOccurred())
			call := mockClient.EXPECT().UpdateRoute(gomock.Any(), gomock.Any()).Times(1)
			testPolicyMsg(bs, call)
		})

		var _ = It("return no error when handling RouteRemove", func() {
			msg := &proto.RouteRemove{Dst: "2.2.2.2"}
			envelope, err := wrapPayloadWithEnvelope(msg, 0)
			Expect(err).ShouldNot(HaveOccurred())
			bs, err := envelope.Marshal()
			Expect(err).ShouldNot(HaveOccurred())
			call := mockClient.EXPECT().RemoveRoute(gomock.Any(), gomock.Any()).Times(1)
			testPolicyMsg(bs, call)
		})

		var _ = It("return no error when handling VXLANTunnelEndpointUpdate", func() {
			msg := &proto.VXLANTunnelEndpointUpdate{Node: "dummy", Mac: "ca:df:aa:0d:29:26", Ipv4Addr: "1.1.1.1", ParentDeviceIp: "3.3.3.3"}
			envelope, err := wrapPayloadWithEnvelope(msg, 0)
			Expect(err).ShouldNot(HaveOccurred())
			bs, err := envelope.Marshal()
			Expect(err).ShouldNot(HaveOccurred())
			call := mockClient.EXPECT().UpdateVXLANTunnelEndpoint(gomock.Any(), gomock.Any()).Times(1)
			testPolicyMsg(bs, call)
		})

		var _ = It("return no error when handling VXLANTunnelEndpointRemove", func() {
			msg := &proto.VXLANTunnelEndpointRemove{Node: "dummy"}
			envelope, err := wrapPayloadWithEnvelope(msg, 0)
			Expect(err).ShouldNot(HaveOccurred())
			bs, err := envelope.Marshal()
			Expect(err).ShouldNot(HaveOccurred())
			call := mockClient.EXPECT().RemoveVXLANTunnelEndpoint(gomock.Any(), gomock.Any()).Times(1)
			testPolicyMsg(bs, call)
		})

		var _ = It("return no error on not handled messages", func() {
			var t tomb.Tomb
			srv, err := NewPolicyServer(logrus.NewEntry(logrus.StandardLogger()))
			Expect(err).ToNot(HaveOccurred())
			Expect(srv).NotTo(BeNil())
			t.Go(func() error {
				defer GinkgoRecover()
				// do not call Start fake accept
				srvConn, err := socketListener.Accept()
				if err != nil {
					// unexpected
					return err
				}
				// will block
				go srv.(*PolicyServer).SyncPolicy(srvConn)
				<-t.Dying()
				return nil
			})

			conn, err := socketListener.Dial()
			Expect(err).ShouldNot(HaveOccurred())

			// write ConfigUpdate
			config := &proto.ConfigUpdate{Config: make(map[string]string)}
			envelope, err := wrapPayloadWithEnvelope(config, 0)
			Expect(err).ShouldNot(HaveOccurred())
			bs, err := envelope.Marshal()
			Expect(err).ShouldNot(HaveOccurred())
			err = writeTo(conn, bs)
			Expect(err).ShouldNot(HaveOccurred())

			// write InSync
			insync := &proto.InSync{}
			envelope, err = wrapPayloadWithEnvelope(insync, 0)
			Expect(err).ShouldNot(HaveOccurred())
			bs, err = envelope.Marshal()
			Expect(err).ShouldNot(HaveOccurred())
			err = writeTo(conn, bs)
			Expect(err).ShouldNot(HaveOccurred())

			// write IpamPoolUpdate
			ipamPoolUpdate := &proto.IPAMPoolUpdate{Id: "dummy", Pool: &proto.IPAMPool{Cidr: "1.2.3.4/24", Masquerade: false}}
			envelope, err = wrapPayloadWithEnvelope(ipamPoolUpdate, 0)
			Expect(err).ShouldNot(HaveOccurred())
			bs, err = envelope.Marshal()
			Expect(err).ShouldNot(HaveOccurred())
			writeErr := writeTo(conn, bs)
			Expect(writeErr).ShouldNot(HaveOccurred())

			// write IpamPoolRemove
			ipamPoolRemove := &proto.IPAMPoolRemove{Id: "dummy"}
			envelope, err = wrapPayloadWithEnvelope(ipamPoolRemove, 0)
			Expect(err).ShouldNot(HaveOccurred())
			bs, err = envelope.Marshal()
			Expect(err).ShouldNot(HaveOccurred())
			err = writeTo(conn, bs)
			Expect(err).ShouldNot(HaveOccurred())

			// write WireguardEndpointUpdate
			wireguardEndpointUpdate := &proto.WireguardEndpointUpdate{Hostname: "dummy", PublicKey: "dummy", InterfaceIpv4Addr: "dummy"}
			envelope, err = wrapPayloadWithEnvelope(wireguardEndpointUpdate, 0)
			Expect(err).ShouldNot(HaveOccurred())
			bs, err = envelope.Marshal()
			Expect(err).ShouldNot(HaveOccurred())
			err = writeTo(conn, bs)
			Expect(err).ShouldNot(HaveOccurred())

			// write WireguardEndpointRemove
			wireguardEndpointRemove := &proto.WireguardEndpointRemove{Hostname: "dummy"}
			envelope, err = wrapPayloadWithEnvelope(wireguardEndpointRemove, 0)
			Expect(err).ShouldNot(HaveOccurred())
			bs, err = envelope.Marshal()
			Expect(err).ShouldNot(HaveOccurred())
			err = writeTo(conn, bs)
			Expect(err).ShouldNot(HaveOccurred())

			// write GlobalBGPConfigUpdate
			bgpUpdate := &proto.GlobalBGPConfigUpdate{ServiceClusterCidrs: []string{"1.1.1.1/24"}, ServiceLoadbalancerCidrs: []string{"2.2.2.2/24"}}
			envelope, err = wrapPayloadWithEnvelope(bgpUpdate, 0)
			Expect(err).ShouldNot(HaveOccurred())
			bs, err = envelope.Marshal()
			Expect(err).ShouldNot(HaveOccurred())
			err = writeTo(conn, bs)
			Expect(err).ShouldNot(HaveOccurred())

			allDone := make(chan bool)
			go func() {
				d, err := time.ParseDuration("100ms")
				if err != nil {
					allDone <- true
				}
				time.Sleep(d)
				allDone <- true
			}()
			// all done there is no way to check if all was processed just wait
			check := <-allDone
			Eventually(func() bool {
				return check
			}).Should(BeTrue())
			t.Kill(errors.New("stop"))
			err = t.Wait()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).Should(Equal("stop"))

		})
	})

	var _ = Context("SendMessage() should", func() {
		var _ = It("return no error when sending ProcessStatusUpdate", func() {
			msg := &proto.ProcessStatusUpdate{IsoTimestamp: "12315", Uptime: 232145123}
			testSendMessage(msg)
		})
		var _ = It("return no error when sending WorkloadEndpointStatusUpdate", func() {
			msg := &proto.WorkloadEndpointStatusUpdate{Id: &proto.WorkloadEndpointID{OrchestratorId: "k8s", WorkloadId: "dummy", EndpointId: "dummy"}}
			testSendMessage(msg)
		})
		var _ = It("return no error when sending WorkloadEndpointStatusRemove", func() {
			msg := &proto.WorkloadEndpointStatusRemove{Id: &proto.WorkloadEndpointID{OrchestratorId: "k8s", WorkloadId: "dummy", EndpointId: "dummy"}}
			testSendMessage(msg)
		})
		var _ = It("return no error when sending HostEndpointStatusUpdate", func() {
			msg := &proto.HostEndpointStatusUpdate{Id: &proto.HostEndpointID{EndpointId: "dummy"}, Status: &proto.EndpointStatus{Status: "dummy"}}
			testSendMessage(msg)
		})
		var _ = It("return no error when sending HostEndpointStatusRemove", func() {
			msg := &proto.HostEndpointStatusRemove{Id: &proto.HostEndpointID{EndpointId: "dummy"}}
			testSendMessage(msg)
		})
		var _ = It("return no error when sending WireguardStatusUpdate", func() {
			msg := &proto.WireguardStatusUpdate{PublicKey: "dummy"}
			testSendMessage(msg)
		})
	})
})
