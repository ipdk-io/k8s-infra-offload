package netconf

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/golang/mock/gomock"
	"github.com/ipdk-io/k8s-infra-offload/pkg/mock_proto"
	"github.com/ipdk-io/k8s-infra-offload/pkg/pool"
	"github.com/ipdk-io/k8s-infra-offload/pkg/types"
	"github.com/ipdk-io/k8s-infra-offload/pkg/utils"
	"github.com/ipdk-io/k8s-infra-offload/proto"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

const (
	bufSize = 1024 * 1024
)

var (
	ipAddr       = net.IPv4(192, 168, 0, 2)
	mask         = net.CIDRMask(24, 32)
	testIfIndex  = 424242
	mockCrtl     *gomock.Controller
	mockClient   *mock_proto.MockInfraAgentClient
	listener     *bufconn.Listener
	globalTestNs ns.NetNS
	tempDir      string
)

func TestUtils(t *testing.T) {
	mockCrtl = gomock.NewController(t)
	mockClient = mock_proto.NewMockInfraAgentClient(mockCrtl)
	RegisterFailHandler(Fail)
	RunSpecs(t, "Netconf Test Suite")
}

var _ = BeforeSuite(func() {
	listener = bufconn.Listen(bufSize)
	utilsGetDataDirPath = func(t string) string {
		return tempDir
	}
})

var _ = AfterSuite(func() {
	mockCrtl.Finish()
	listener.Close()
	_ = os.RemoveAll(tempDir)
})

var _ = Describe("netconf", func() {
	var _ = BeforeEach(func() {
		var err error
		tempDir, err = os.MkdirTemp("", "test")
		Expect(err).ShouldNot(HaveOccurred())
		saveInterfaceConf = fakeSaveInterfaceConf
		readInterfaceConf = fakeReadInterfaceConf
	})

	var _ = AfterEach(func() {
		_ = os.RemoveAll(tempDir)
	})

	var _ = Context("setupContainerRoutes() should", func() {
		var _ = It("return no error", func() {
			ipAddRoute = fakeAddRoute
			err := setupContainerRoutes(&fakeLink{}, net.IP{}, []string{"192.168.0.0/24"})
			Expect(err).ToNot(HaveOccurred())
		})
		var _ = It("setupContainerRoutes() should return no error if IPv6 was used", func() {
			ipAddRoute = fakeAddRoute
			err := setupContainerRoutes(&fakeLink{}, net.IP{}, []string{"::/128"})
			Expect(err).ToNot(HaveOccurred())
		})
		var _ = It("return no error if IPv6 was used", func() {
			ipAddRoute = fakeAddRoute
			err := setupContainerRoutes(&fakeLink{}, net.IP{}, []string{"192.168.0.0"})
			Expect(err).ToNot(HaveOccurred())
		})
		var _ = It("return error if can't add route", func() {
			ipAddRoute = fakeAddRouteErr
			err := setupContainerRoutes(&fakeLink{}, net.IP{}, []string{"192.168.0.0/24"})
			Expect(err).To(HaveOccurred())
		})
	})

	var _ = Context("setLinkAddress() should", func() {
		var _ = It("return no error", func() {
			addrAdd = fakeAddrAddDel
			err := setLinkAddress(&fakeLink{}, []*proto.IPConfig{{Address: "192.168.0.2/24", Gateway: "192.168.0.1"}})
			Expect(err).ToNot(HaveOccurred())
		})
		var _ = It("return no error if gateway address cannot be parsed", func() {
			addrAdd = fakeAddrAddDel
			err := setLinkAddress(&fakeLink{}, []*proto.IPConfig{{Address: "Bad IP", Gateway: "192.168.0.1"}})
			Expect(err).ToNot(HaveOccurred())
		})
		var _ = It("return error if cannot set link address", func() {
			addrAdd = fakeAddrAddDelErr
			err := setLinkAddress(&fakeLink{}, []*proto.IPConfig{{Address: "192.168.0.2/24", Gateway: "192.168.0.1"}})
			Expect(err).To(HaveOccurred())
		})
	})

	var _ = Context("setupPodRoute() should", func() {
		var _ = It("return error if cannot parse gateway IP", func() {
			ipAddRoute = fakeAddRoute
			err := setupPodRoute(&fakeLink{}, []string{"192.168.0.0/24"}, "badAddress")
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return no error", func() {
			ipAddRoute = fakeAddRoute
			err := setupPodRoute(&fakeLink{}, []string{"192.168.0.0/24"}, nonTargetIP)
			Expect(err).ToNot(HaveOccurred())
		})
	})

	var _ = Context("setupHostRoute() should", func() {
		var _ = It("return error if cannot list routes", func() {
			routeListFiltered = fakeRouteListFilteredErr
			err := setupHostRoute(&net.IPNet{IP: ipAddr, Mask: mask}, &fakeLink{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return no error if route already exists", func() {
			routeListFiltered = fakeRouteListFilteredExisting
			err := setupHostRoute(&net.IPNet{IP: ipAddr, Mask: mask}, &fakeLink{})
			Expect(err).ToNot(HaveOccurred())
		})
		var _ = It("return no error if route is to be deleted", func() {
			routeListFiltered = fakeRouteListFiltereToBeDeleted
			routeDel = fakeRouteHandle
			routeAdd = fakeRouteHandle
			err := setupHostRoute(&net.IPNet{IP: ipAddr, Mask: mask}, &fakeLink{})
			Expect(err).ToNot(HaveOccurred())
		})
		var _ = It("return error if cannot add route", func() {
			routeListFiltered = fakeRouteListFiltereToBeDeleted
			routeDel = fakeRouteHandle
			routeAdd = fakeRouteHandleErr
			err := setupHostRoute(&net.IPNet{IP: ipAddr, Mask: mask}, &fakeLink{})
			Expect(err).To(HaveOccurred())
		})
	})

	var _ = Context("NewTapPodInterface() should", func() {
		var _ = It("return error if cannot get tap interfaces", func() {
			getTapInterfaces = fakeGetTapInterfacesErr
			_, err := NewTapPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if slice of tap interfaces is empty", func() {
			getTapInterfaces = fakeGetTapInterfacesEmpty
			_, err := NewTapPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot get Host IP from Pod CIDR", func() {
			getTapInterfaces = fakeGetTapInterfacesSingle
			_, err := NewTapPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot configure host interface", func() {
			getTapInterfaces = fakeGetTapInterfacesSingle
			configureHostInterfaceFunc = fakeConfigureHostInterfaceErr
			_, err := NewTapPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if failed on send host interface configure request to manager", func() {
			getTapInterfaces = fakeGetTapInterfacesSingle
			configureHostInterfaceFunc = fakeConfigureHostInterface
			sendSetupHostInterfaceFunc = fakeSendSetupHostInterfaceErr
			_, err := NewTapPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return no error", func() {
			getTapInterfaces = fakeGetTapInterfacesSingle
			configureHostInterfaceFunc = fakeConfigureHostInterface
			sendSetupHostInterfaceFunc = fakeSendSetupHostInterface
			_, err := NewTapPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
		})
	})

	var _ = Context("configureHostInterface() should", func() {
		var _ = It("return error if cannot get link", func() {
			linkByName = fakeLinkByNameErr
			err := configureHostInterface("dummyIf", &net.IPNet{}, []*types.InterfaceInfo{}, logrus.NewEntry(logrus.New()))
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot list IPs for link", func() {
			linkByName = fakeLinkByName
			addrList = fakeAddrListErr
			err := configureHostInterface("dummyIf", &net.IPNet{}, []*types.InterfaceInfo{}, logrus.NewEntry(logrus.New()))
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot add IP address", func() {
			linkByName = fakeLinkByName
			addrList = fakeAddrList
			addrDel = fakeAddrAddDelErr
			addrAdd = fakeAddrAddDelErr
			err := configureHostInterface("dummyIf", &net.IPNet{}, []*types.InterfaceInfo{}, logrus.NewEntry(logrus.New()))
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot set link up", func() {
			linkByName = fakeLinkByName
			addrList = fakeAddrList
			addrDel = fakeAddrAddDelErr
			addrAdd = fakeAddrAddDel
			linkSetUp = fakeLinkSetErr
			err := configureHostInterface("dummyIf", &net.IPNet{}, []*types.InterfaceInfo{}, logrus.NewEntry(logrus.New()))
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot configure routing", func() {
			linkByName = fakeLinkByName
			addrList = fakeAddrList
			addrDel = fakeAddrAddDelErr
			addrAdd = fakeAddrAddDel
			linkSetUp = fakeLinkSet
			configureRoutingFunc = fakeConfigureRoutingErr
			err := configureHostInterface("dummyIf", &net.IPNet{}, []*types.InterfaceInfo{}, logrus.NewEntry(logrus.New()))
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return no error", func() {
			linkByName = fakeLinkByName
			addrList = fakeAddrList
			addrDel = fakeAddrAddDelErr
			addrAdd = fakeAddrAddDel
			linkSetUp = fakeLinkSet
			configureRoutingFunc = fakeConfigureRouting
			err := configureHostInterface("dummyIf", &net.IPNet{}, []*types.InterfaceInfo{}, logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
		})
	})

	var _ = Context("configureRoutingForCIDR() should", func() {
		var _ = It("return error if cannot parse CIDR", func() {
			cidr := "badCidr"
			err := configureRoutingForCIDR(&fakeLink{}, cidr, logrus.NewEntry(logrus.New()))
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot setup host route", func() {
			cidr := "10.210.0.0/24"
			routeListFiltered = fakeRouteListFilteredErr
			err := configureRoutingForCIDR(&fakeLink{}, cidr, logrus.NewEntry(logrus.New()))
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return no error", func() {
			cidr := "10.210.0.0/24"
			routeListFiltered = fakeRouteListFiltereToBeDeleted
			routeDel = fakeRouteHandle
			routeAdd = fakeRouteHandle
			err := configureRoutingForCIDR(&fakeLink{}, cidr, logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
		})
	})

	var _ = Context("configureRouting() should", func() {
		var _ = It("return no error", func() {
			types.ClusterPodsCIDR = "10.210.0.0/16"
			types.NodePodsCIDR = "10.210.0.0/24"
			types.ClusterServicesSubnet = "10.96.0.0/16"
			routeListFiltered = fakeRouteListFiltereToBeDeleted
			routeDel = fakeRouteHandle
			routeAdd = fakeRouteHandle
			err := configureRouting(&fakeLink{}, logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
		})
		var _ = It("return error if cannot setup ClusterPodsCIDR routing", func() {
			types.ClusterPodsCIDR = "badCidr"
			types.NodePodsCIDR = "10.210.0.0/24"
			routeListFiltered = fakeRouteListFiltereToBeDeleted
			routeDel = fakeRouteHandle
			routeAdd = fakeRouteHandle
			err := configureRouting(&fakeLink{}, logrus.NewEntry(logrus.New()))
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot setup ClusterServicesSubnet routing", func() {
			types.ClusterPodsCIDR = "10.210.0.0/16"
			types.NodePodsCIDR = "10.210.0.0/24"
			types.ClusterServicesSubnet = "badCidr"
			routeListFiltered = fakeRouteListFiltereToBeDeleted
			routeDel = fakeRouteHandle
			routeAdd = fakeRouteHandle
			err := configureRouting(&fakeLink{}, logrus.NewEntry(logrus.New()))
			Expect(err).To(HaveOccurred())
		})
	})

	var _ = Context("sendSetupHostInterface() should", func() {
		var _ = It("return no error", func() {
			grpcDial = fakeGrpcDialErr
			err := sendSetupHostInterface(&proto.SetupHostInterfaceRequest{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if request to manager returned error", func() {
			grpcDial = fakeGrpcDial
			newInfraAgentClient = newFakeClient
			gomock.InOrder(mockClient.EXPECT().SetupHostInterface(gomock.Any(), gomock.Any()).Return(&proto.Reply{Successful: false}, errors.New("Error")))
			err := sendSetupHostInterface(&proto.SetupHostInterfaceRequest{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if request to is not successfull", func() {
			grpcDial = fakeGrpcDial
			newInfraAgentClient = newFakeClient
			gomock.InOrder(mockClient.EXPECT().SetupHostInterface(gomock.Any(), gomock.Any()).Return(&proto.Reply{Successful: false, ErrorMessage: "Fake error message"}, nil))
			err := sendSetupHostInterface(&proto.SetupHostInterfaceRequest{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return no error", func() {
			grpcDial = fakeGrpcDial
			newInfraAgentClient = newFakeClient
			gomock.InOrder(mockClient.EXPECT().SetupHostInterface(gomock.Any(), gomock.Any()).Return(&proto.Reply{Successful: true}, nil))
			err := sendSetupHostInterface(&proto.SetupHostInterfaceRequest{})
			Expect(err).ToNot(HaveOccurred())
		})
	})

	var _ = Context("CreatePodInterface() should", func() {
		var _ = It("return error if there are no available interfaces", func() {
			getTapInterfaces = fakeGetTapInterfacesSingle
			configureHostInterfaceFunc = fakeConfigureHostInterface
			pi, err := NewTapPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
			_, err = pi.CreatePodInterface(&proto.AddRequest{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot set host interface in pod netns", func() {
			getTapInterfaces = fakeGetTapInterfacesMultiple
			configureHostInterfaceFunc = fakeConfigureHostInterface
			pi, err := NewTapPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
			setHostInterfaceInPodNetnsFunc = fakeSetHostInterfaceInPodNetnsErr
			_, err = pi.CreatePodInterface(&proto.AddRequest{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot set host interface in pod netns inside container", func() {
			getTapInterfaces = fakeGetTapInterfacesMultiple
			configureHostInterfaceFunc = fakeConfigureHostInterface
			pi, err := NewTapPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
			setHostInterfaceInPodNetnsFunc = fakeSetHostInterfaceInPodNetnsErrInNs
			_, err = pi.CreatePodInterface(&proto.AddRequest{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot save interface configuration", func() {
			getTapInterfaces = fakeGetTapInterfacesMultiple
			configureHostInterfaceFunc = fakeConfigureHostInterface
			pi, err := NewTapPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
			setHostInterfaceInPodNetnsFunc = fakeSetHostInterfaceInPodNetns
			saveInterfaceConf = fakeSaveInterfaceConfErr
			_, err = pi.CreatePodInterface(&proto.AddRequest{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return no error", func() {
			getTapInterfaces = fakeGetTapInterfacesMultiple
			configureHostInterfaceFunc = fakeConfigureHostInterface
			sendSetupHostInterfaceFunc = fakeSendSetupHostInterface
			pi, err := NewTapPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
			setHostInterfaceInPodNetnsFunc = fakeSetHostInterfaceInPodNetns
			saveInterfaceConf = fakeSaveInterfaceConf
			_, err = pi.CreatePodInterface(&proto.AddRequest{})
			Expect(err).ToNot(HaveOccurred())
		})
	})

	var _ = Context("ReleasePodInterface() should", func() {
		var _ = It("return error when cannot read interface conf", func() {
			getTapInterfaces = fakeGetTapInterfacesMultiple
			configureHostInterfaceFunc = fakeConfigureHostInterface
			pi, err := NewTapPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
			setHostInterfaceInPodNetnsFunc = fakeSetHostInterfaceInPodNetns
			readInterfaceConf = fakeReadInterfaceConfErr
			err = pi.ReleasePodInterface(&proto.DelRequest{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return no error when conf does not exist", func() {
			getTapInterfaces = fakeGetTapInterfacesMultiple
			configureHostInterfaceFunc = fakeConfigureHostInterface
			pi, err := NewTapPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
			setHostInterfaceInPodNetnsFunc = fakeSetHostInterfaceInPodNetns
			readInterfaceConf = fakeReadInterfaceConfNotExist
			err = pi.ReleasePodInterface(&proto.DelRequest{})
			Expect(err).ToNot(HaveOccurred())
		})
		var _ = It("return error when cannot move pod interface to host", func() {
			getTapInterfaces = fakeGetTapInterfacesMultiple
			configureHostInterfaceFunc = fakeConfigureHostInterface
			pi, err := NewTapPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
			setHostInterfaceInPodNetnsFunc = fakeSetHostInterfaceInPodNetns
			readInterfaceConf = fakeReadInterfaceConf
			movePodInterfaceToHostNetnsFunc = fakeMovePodInterfaceToHostNetnsErr
			err = pi.ReleasePodInterface(&proto.DelRequest{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return no error", func() {
			getTapInterfaces = fakeGetTapInterfacesMultiple
			configureHostInterfaceFunc = fakeConfigureHostInterface
			pi, err := NewTapPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
			setHostInterfaceInPodNetnsFunc = fakeSetHostInterfaceInPodNetns
			readInterfaceConf = fakeReadInterfaceConf
			movePodInterfaceToHostNetnsFunc = fakeMovePodInterfaceToHostNetns
			err = pi.ReleasePodInterface(&proto.DelRequest{})
			Expect(err).ToNot(HaveOccurred())
		})
	})

	var _ = Context("SetupNetwork() should", func() {
		var _ = It("return error if cannot create network", func() {
			getTapInterfaces = fakeGetTapInterfacesMultiple
			configureHostInterfaceFunc = fakeConfigureHostInterface
			pi, err := NewTapPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
			gomock.InOrder(mockClient.EXPECT().CreateNetwork(gomock.Any(), gomock.Any()).Return(&proto.AddReply{Successful: false}, errors.New("Error")))
			_, err = pi.SetupNetwork(context.TODO(), mockClient, &types.InterfaceInfo{}, &proto.AddRequest{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot create network", func() {
			getTapInterfaces = fakeGetTapInterfacesMultiple
			configureHostInterfaceFunc = fakeConfigureHostInterface
			pi, err := NewTapPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
			gomock.InOrder(mockClient.EXPECT().CreateNetwork(gomock.Any(), gomock.Any()).Return(&proto.AddReply{Successful: true}, nil))
			_, err = pi.SetupNetwork(context.TODO(), mockClient, &types.InterfaceInfo{}, &proto.AddRequest{})
			Expect(err).ToNot(HaveOccurred())
		})
	})

	var _ = Context("ReleaseNetwork() should", func() {
		var _ = It("return error if cannot read interface conf", func() {
			getTapInterfaces = fakeGetTapInterfacesMultiple
			configureHostInterfaceFunc = fakeConfigureHostInterface
			pi, err := NewTapPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
			readInterfaceConf = fakeReadInterfaceConfErr
			_, err = pi.ReleaseNetwork(context.TODO(), mockClient, &proto.DelRequest{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return no error if cannot interface conf does not exist", func() {
			getTapInterfaces = fakeGetTapInterfacesMultiple
			configureHostInterfaceFunc = fakeConfigureHostInterface
			pi, err := NewTapPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
			readInterfaceConf = fakeReadInterfaceConfNotExist
			_, err = pi.ReleaseNetwork(context.TODO(), mockClient, &proto.DelRequest{})
			Expect(err).ToNot(HaveOccurred())
		})
		var _ = It("return no error if namespace already gone", func() {
			getTapInterfaces = fakeGetTapInterfacesMultiple
			configureHostInterfaceFunc = fakeConfigureHostInterface
			linkByName = fakeLinkByName
			addrList = fakeAddrList
			pi, err := NewTapPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
			readInterfaceConf = fakeReadInterfaceConf
			_, err = pi.ReleaseNetwork(context.TODO(), mockClient, &proto.DelRequest{})
			Expect(err).ToNot(HaveOccurred())
		})
		var _ = It("return error if cannot get link by name", func() {
			getTapInterfaces = fakeGetTapInterfacesMultiple
			configureHostInterfaceFunc = fakeConfigureHostInterface
			pi, err := NewTapPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
			readInterfaceConf = fakeReadInterfaceConf
			linkByName = fakeLinkByNameErr
			addrList = fakeAddrListErr
			withNetNSPath = fakeWithNetNSPath
			_, err = pi.ReleaseNetwork(context.TODO(), mockClient, &proto.DelRequest{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot list addresses", func() {
			getTapInterfaces = fakeGetTapInterfacesMultiple
			configureHostInterfaceFunc = fakeConfigureHostInterface
			pi, err := NewTapPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
			readInterfaceConf = fakeReadInterfaceConf
			linkByName = fakeLinkByName
			addrList = fakeAddrListErr
			withNetNSPath = fakeWithNetNSPath
			ctx := context.TODO()
			_, err = pi.ReleaseNetwork(ctx, mockClient, &proto.DelRequest{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return no error", func() {
			getTapInterfaces = fakeGetTapInterfacesMultiple
			configureHostInterfaceFunc = fakeConfigureHostInterface
			addrList = fakeAddrList
			linkByName = fakeLinkByName
			pi, err := NewTapPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
			readInterfaceConf = fakeReadInterfaceConf
			linkByName = fakeLinkByName
			addrList = fakeAddrList
			withNetNSPath = fakeWithNetNSPath
			gomock.InOrder(mockClient.EXPECT().DeleteNetwork(gomock.Any(), gomock.Any()).Return(&proto.DelReply{Successful: true}, nil))
			_, err = pi.ReleaseNetwork(context.TODO(), mockClient, &proto.DelRequest{})
			Expect(err).ToNot(HaveOccurred())
		})
	})

	var _ = Context("setHostInterfaceInPodNetns() should", func() {
		var _ = It("return error if cannot get netNS", func() {
			getNS = fakeGetNSErr
			err := setHostInterfaceInPodNetns(&proto.AddRequest{}, &types.InterfaceInfo{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot get link by name", func() {
			getNS = fakeGetNS
			linkByName = fakeLinkByNameErr
			err := setHostInterfaceInPodNetns(&proto.AddRequest{}, &types.InterfaceInfo{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot set link down", func() {
			getNS = fakeGetNS
			linkByName = fakeLinkByName
			linkSetDown = fakeLinkSetErr
			err := setHostInterfaceInPodNetns(&proto.AddRequest{}, &types.InterfaceInfo{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot set MTU", func() {
			getNS = fakeGetNS
			linkByName = fakeLinkByName
			linkSetDown = fakeLinkSet
			linkSetMTU = fakeLinkSetValueErr
			err := setHostInterfaceInPodNetns(&proto.AddRequest{Settings: &proto.ContainerSettings{Mtu: 1500}}, &types.InterfaceInfo{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot set NS fd", func() {
			getNS = fakeGetNS
			linkByName = fakeLinkByName
			linkSetDown = fakeLinkSet
			linkSetMTU = fakeLinkSetValue
			linkSetNsFd = fakeLinkSetValueErr
			err := setHostInterfaceInPodNetns(&proto.AddRequest{Settings: &proto.ContainerSettings{Mtu: 1500}}, &types.InterfaceInfo{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot set NS fd", func() {
			getNS = fakeGetNS
			linkByName = fakeLinkByName
			linkSetDown = fakeLinkSet
			linkSetMTU = fakeLinkSetValue
			linkSetNsFd = fakeLinkSetValue
			withNetNSPath = fakeWithNetNSPathErr
			err := setHostInterfaceInPodNetns(&proto.AddRequest{Settings: &proto.ContainerSettings{Mtu: 1500}}, &types.InterfaceInfo{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return no error", func() {
			getNS = fakeGetNS
			linkByName = fakeLinkByName
			linkSetDown = fakeLinkSet
			linkSetMTU = fakeLinkSetValue
			linkSetNsFd = fakeLinkSetValue
			withNetNSPath = fakeWithNetNSPathSuccessful
			err := setHostInterfaceInPodNetns(&proto.AddRequest{Settings: &proto.ContainerSettings{Mtu: 1500}}, &types.InterfaceInfo{})
			Expect(err).ToNot(HaveOccurred())
		})
	})

	var _ = Context("configureTapNamespace() should", func() {
		var _ = It("return error if cannot set link name", func() {
			withNetNSPath = fakeWithNetNSPath
			linkSetName = fakeLinkSetNameErr
			err := configureTapNamespace(&proto.AddRequest{Settings: &proto.ContainerSettings{Mtu: 0}, ContainerRoutes: []string{"192.168.0.0/24"}}, &fakeLink{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot get link by name", func() {
			withNetNSPath = fakeWithNetNSPath
			linkSetName = fakeLinkSetName
			linkByName = fakeLinkByNameErr
			err := configureTapNamespace(&proto.AddRequest{Settings: &proto.ContainerSettings{Mtu: 0}, ContainerRoutes: []string{"192.168.0.0/24"}}, &fakeLink{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot set link address", func() {
			withNetNSPath = fakeWithNetNSPath
			linkSetName = fakeLinkSetName
			linkByName = fakeLinkByName
			ipAddRoute = fakeAddRoute
			setLinkAddressFunc = fakeSetLinkAddressErr
			err := configureTapNamespace(&proto.AddRequest{Settings: &proto.ContainerSettings{Mtu: 0}, ContainerRoutes: []string{"192.168.0.0/24"}}, &fakeLink{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot set link up", func() {
			withNetNSPath = fakeWithNetNSPath
			linkSetName = fakeLinkSetName
			linkByName = fakeLinkByName
			ipAddRoute = fakeAddRoute
			setLinkAddressFunc = fakeSetLinkAddress
			linkSetUp = fakeLinkSetErr
			err := configureTapNamespace(&proto.AddRequest{Settings: &proto.ContainerSettings{Mtu: 0}, ContainerRoutes: []string{"192.168.0.0/24"}}, &fakeLink{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot set set pod route", func() {
			withNetNSPath = fakeWithNetNSPath
			linkSetName = fakeLinkSetName
			linkByName = fakeLinkByName
			ipAddRoute = fakeAddRouteErr
			linkSetUp = fakeLinkSet
			err := configureTapNamespace(&proto.AddRequest{Settings: &proto.ContainerSettings{Mtu: 0}, ContainerRoutes: []string{"192.168.0.0/24"}}, &fakeLink{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return no error", func() {
			withNetNSPath = fakeWithNetNSPath
			linkSetName = fakeLinkSetName
			linkByName = fakeLinkByName
			ipAddRoute = fakeAddRoute
			linkSetUp = fakeLinkSet
			err := configureTapNamespace(&proto.AddRequest{Settings: &proto.ContainerSettings{Mtu: 0}, ContainerRoutes: []string{"192.168.0.0/24"}}, &fakeLink{})
			Expect(err).ToNot(HaveOccurred())
		})
	})

	var _ = Context("movePodInterfaceToHostNetns() should", func() {
		var _ = It("return error if cannot get current namespace", func() {
			getCurrentNS = fakeGetCurrentNSErr
			err := movePodInterfaceToHostNetns("", "", &types.InterfaceInfo{InterfaceName: "dummyIf"})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if failed in  withNetNSPath", func() {
			getCurrentNS = fakeGetCurrentNS
			withNetNSPath = fakeWithNetNSPathErr
			err := movePodInterfaceToHostNetns("", "", &types.InterfaceInfo{InterfaceName: "dummyIf"})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return no error", func() {
			getCurrentNS = fakeGetCurrentNS
			withNetNSPath = fakeWithNetNSPathSuccessful
			err := movePodInterfaceToHostNetns("", "", &types.InterfaceInfo{InterfaceName: "dummyIf"})
			Expect(err).ToNot(HaveOccurred())
		})
		var _ = It("return no error if namespace does not exist", func() {
			getCurrentNS = fakeGetCurrentNS
			withNetNSPath = fakeWithNetNSPathErrNotExist
			err := movePodInterfaceToHostNetns("", "", &types.InterfaceInfo{InterfaceName: "dummyIf"})
			Expect(err).ToNot(HaveOccurred())
		})
		var _ = It("return error if cannot get link by name", func() {
			getCurrentNS = fakeGetCurrentNS
			withNetNSPath = fakeWithNetNSPath
			linkByName = fakeLinkByNameErr
			err := movePodInterfaceToHostNetns("", "", &types.InterfaceInfo{InterfaceName: "dummyIf"})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot set link down", func() {
			getCurrentNS = fakeGetCurrentNS
			withNetNSPath = fakeWithNetNSPath
			linkByName = fakeLinkByName
			linkSetDown = fakeLinkSetErr
			err := movePodInterfaceToHostNetns("", "", &types.InterfaceInfo{InterfaceName: "dummyIf"})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot set interface name", func() {
			getCurrentNS = fakeGetCurrentNS
			withNetNSPath = fakeWithNetNSPath
			linkByName = fakeLinkByName
			linkSetDown = fakeLinkSet
			readInterfaceConf = fakeReadInterfaceConf
			linkSetName = fakeLinkSetNameErr
			err := movePodInterfaceToHostNetns("", "", &types.InterfaceInfo{InterfaceName: "dummyIf"})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot set namespace fd", func() {
			getCurrentNS = fakeGetCurrentNS
			withNetNSPath = fakeWithNetNSPath
			linkByName = fakeLinkByName
			linkSetDown = fakeLinkSet
			readInterfaceConf = fakeReadInterfaceConf
			linkSetName = fakeLinkSetName
			linkSetNsFd = fakeLinkSetValueErr
			err := movePodInterfaceToHostNetns("", "", &types.InterfaceInfo{InterfaceName: "dummyIf"})
			Expect(err).To(HaveOccurred())
		})
	})

	var _ = Context("NewSriovPodInterface() should", func() {
		var _ = It("return error if cannot get VF interfaces", func() {
			getVFList = fakeGetVFListErr
			_, err := NewSriovPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if slice of VF interfaces is empty", func() {
			getVFList = fakeGetVFList
			_, err := NewSriovPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot get link by name", func() {
			getVFList = fakeGetVFListSingle
			linkByName = fakeLinkByNameErr
			_, err := NewSriovPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot add address", func() {
			getVFList = fakeGetVFListSingle
			linkByName = fakeLinkByName
			addrList = fakeAddrListWithResult
			addrDel = fakeAddrAddDel
			releaseIPFromIPAM = fakeReleaseIPFromIPAM
			getIPFromIPAM = fakeGetIPFromIPAM
			addrAdd = fakeAddrAddDelErr
			_, err := NewSriovPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot set link up", func() {
			getVFList = fakeGetVFListSingle
			linkByName = fakeLinkByName
			addrList = fakeAddrListWithResult
			addrDel = fakeAddrAddDel
			releaseIPFromIPAM = fakeReleaseIPFromIPAM
			getIPFromIPAM = fakeGetIPFromIPAM
			addrAdd = fakeAddrAddDel
			linkSetUp = fakeLinkSetErr
			_, err := NewSriovPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot configure routing", func() {
			getVFList = fakeGetVFListSingle
			linkByName = fakeLinkByName
			addrList = fakeAddrListWithResult
			addrDel = fakeAddrAddDel
			releaseIPFromIPAM = fakeReleaseIPFromIPAM
			getIPFromIPAM = fakeGetIPFromIPAM
			addrAdd = fakeAddrAddDel
			linkSetUp = fakeLinkSet
			configureRoutingFunc = fakeConfigureRoutingErr
			_, err := NewSriovPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if failed on sending setup host interface request to manager", func() {
			getVFList = fakeGetVFListSingle
			linkByName = fakeLinkByName
			addrList = fakeAddrListWithResult
			addrDel = fakeAddrAddDel
			releaseIPFromIPAM = fakeReleaseIPFromIPAM
			getIPFromIPAM = fakeGetIPFromIPAM
			addrAdd = fakeAddrAddDel
			linkSetUp = fakeLinkSet
			configureRoutingFunc = fakeConfigureRouting
			sendSetupHostInterfaceFunc = fakeSendSetupHostInterfaceErr
			_, err := NewSriovPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return no error", func() {
			getVFList = fakeGetVFListSingle
			linkByName = fakeLinkByName
			addrList = fakeAddrListWithResult
			addrDel = fakeAddrAddDel
			releaseIPFromIPAM = fakeReleaseIPFromIPAM
			getIPFromIPAM = fakeGetIPFromIPAM
			addrAdd = fakeAddrAddDel
			linkSetUp = fakeLinkSet
			configureRoutingFunc = fakeConfigureRouting
			sendSetupHostInterfaceFunc = fakeSendSetupHostInterface
			_, err := NewSriovPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
		})
	})
	var _ = Context("CreatePodInterface() should", func() {
		var _ = It("return error if no resources left", func() {
			getVFList = fakeGetVFListSingle
			linkByName = fakeLinkByName
			addrList = fakeAddrListWithResult
			addrDel = fakeAddrAddDel
			releaseIPFromIPAM = fakeReleaseIPFromIPAM
			getIPFromIPAM = fakeGetIPFromIPAM
			addrAdd = fakeAddrAddDel
			linkSetUp = fakeLinkSet
			configureRoutingFunc = fakeConfigureRouting
			pi, err := NewSriovPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
			_, err = pi.CreatePodInterface(&proto.AddRequest{Settings: &proto.ContainerSettings{}})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("should return error if cannot configure sriov network", func() {
			getVFList = fakeGetVFListMulti
			linkByName = fakeLinkByName
			addrList = fakeAddrListWithResult
			addrDel = fakeAddrAddDel
			releaseIPFromIPAM = fakeReleaseIPFromIPAM
			getIPFromIPAM = fakeGetIPFromIPAM
			addrAdd = fakeAddrAddDel
			linkSetUp = fakeLinkSet
			configureRoutingFunc = fakeConfigureRouting
			doSriovNetworkFunc = fakeSetHostInterfaceInPodNetnsErr
			pi, err := NewSriovPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
			_, err = pi.CreatePodInterface(&proto.AddRequest{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("should return error if cannot configure sriov network when in container's netns", func() {
			getVFList = fakeGetVFListMulti
			linkByName = fakeLinkByName
			addrList = fakeAddrListWithResult
			addrDel = fakeAddrAddDel
			releaseIPFromIPAM = fakeReleaseIPFromIPAM
			getIPFromIPAM = fakeGetIPFromIPAM
			addrAdd = fakeAddrAddDel
			linkSetUp = fakeLinkSet
			configureRoutingFunc = fakeConfigureRouting
			doSriovNetworkFunc = fakeSetHostInterfaceInPodNetnsErrInNs
			pi, err := NewSriovPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
			_, err = pi.CreatePodInterface(&proto.AddRequest{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("should return error if cannot save interface configuration", func() {
			getVFList = fakeGetVFListMulti
			linkByName = fakeLinkByName
			addrList = fakeAddrListWithResult
			addrDel = fakeAddrAddDel
			releaseIPFromIPAM = fakeReleaseIPFromIPAM
			getIPFromIPAM = fakeGetIPFromIPAM
			addrAdd = fakeAddrAddDel
			linkSetUp = fakeLinkSet
			configureRoutingFunc = fakeConfigureRouting
			doSriovNetworkFunc = fakeSetHostInterfaceInPodNetns
			saveInterfaceConf = fakeSaveInterfaceConfErr
			pi, err := NewSriovPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
			_, err = pi.CreatePodInterface(&proto.AddRequest{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("should return no error", func() {
			getVFList = fakeGetVFListMulti
			linkByName = fakeLinkByName
			addrList = fakeAddrListWithResult
			addrDel = fakeAddrAddDel
			releaseIPFromIPAM = fakeReleaseIPFromIPAM
			getIPFromIPAM = fakeGetIPFromIPAM
			addrAdd = fakeAddrAddDel
			linkSetUp = fakeLinkSet
			configureRoutingFunc = fakeConfigureRouting
			doSriovNetworkFunc = fakeSetHostInterfaceInPodNetns
			saveInterfaceConf = fakeSaveInterfaceConf
			pi, err := NewSriovPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
			_, err = pi.CreatePodInterface(&proto.AddRequest{})
			Expect(err).ToNot(HaveOccurred())
		})
	})
	var _ = Context("ReleasePodInterface() should", func() {
		var _ = It("return error if cannot read interface configuration", func() {
			readInterfaceConf = fakeReadInterfaceConfErr
			pi, err := NewSriovPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
			err = pi.ReleasePodInterface(&proto.DelRequest{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot release sriov network", func() {
			readInterfaceConf = fakeReadInterfaceConf
			pi, err := NewSriovPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
			movePodInterfaceToHostNetnsFunc = fakeMovePodInterfaceToHostNetnsErr
			err = pi.ReleasePodInterface(&proto.DelRequest{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return no error", func() {
			readInterfaceConf = fakeReadInterfaceConf
			getCurrentNS = fakeGetCurrentNS
			withNetNSPath = fakeWithNetNSPathSuccessful
			movePodInterfaceToHostNetnsFunc = fakeMovePodInterfaceToHostNetns
			pi, err := NewSriovPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
			err = pi.ReleasePodInterface(&proto.DelRequest{})
			Expect(err).ToNot(HaveOccurred())
		})
	})
	var _ = Context("SetupNetwork() should", func() {
		var _ = It("return error if cannot setup network", func() {
			pi, err := NewSriovPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
			gomock.InOrder(mockClient.EXPECT().CreateNetwork(gomock.Any(), gomock.Any()).Return(&proto.AddReply{Successful: false}, errors.New("Fake error on CreateNetwork")))
			_, err = pi.SetupNetwork(context.TODO(), mockClient, &types.InterfaceInfo{}, &proto.AddRequest{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return no error", func() {
			pi, err := NewSriovPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
			gomock.InOrder(mockClient.EXPECT().CreateNetwork(gomock.Any(), gomock.Any()).Return(&proto.AddReply{Successful: true}, nil))
			_, err = pi.SetupNetwork(context.TODO(), mockClient, &types.InterfaceInfo{}, &proto.AddRequest{})
			Expect(err).ToNot(HaveOccurred())
		})
	})
	var _ = Context("releaseSriovNetwork() should", func() {
		var _ = It("return error if cannot read interface config", func() {
			readInterfaceConf = fakeReadInterfaceConfErr
			pi, err := NewSriovPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
			_, err = pi.ReleaseNetwork(context.TODO(), mockClient, &proto.DelRequest{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot configure netns", func() {
			readInterfaceConf = fakeReadInterfaceConf
			withNetNSPath = fakeWithNetNSPathErr
			pi, err := NewSriovPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
			_, err = pi.ReleaseNetwork(context.TODO(), mockClient, &proto.DelRequest{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return no error if netns does not exist", func() {
			readInterfaceConf = fakeReadInterfaceConf
			withNetNSPath = fakeWithNetNSPathErrNotExist
			pi, err := NewSriovPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
			_, err = pi.ReleaseNetwork(context.TODO(), mockClient, &proto.DelRequest{})
			Expect(err).ToNot(HaveOccurred())
		})
		var _ = It("return error if cannot get link by name", func() {
			readInterfaceConf = fakeReadInterfaceConf
			withNetNSPath = fakeWithNetNSPath
			linkByName = fakeLinkByName
			pi, err := NewSriovPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
			linkByName = fakeLinkByNameErr
			_, err = pi.ReleaseNetwork(context.TODO(), mockClient, &proto.DelRequest{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot list addresses", func() {
			readInterfaceConf = fakeReadInterfaceConf
			withNetNSPath = fakeWithNetNSPath
			linkByName = fakeLinkByName
			addrList = fakeAddrList
			pi, err := NewSriovPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
			addrList = fakeAddrListErr
			_, err = pi.ReleaseNetwork(context.TODO(), mockClient, &proto.DelRequest{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return no error", func() {
			readInterfaceConf = fakeReadInterfaceConf
			withNetNSPath = fakeWithNetNSPath
			linkByName = fakeLinkByName
			addrList = fakeAddrList
			pi, err := NewSriovPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
			gomock.InOrder(mockClient.EXPECT().DeleteNetwork(gomock.Any(), gomock.Any()).Return(&proto.DelReply{Successful: true}, nil))
			_, err = pi.ReleaseNetwork(context.TODO(), mockClient, &proto.DelRequest{})
			Expect(err).ToNot(HaveOccurred())
		})
	})
	var _ = Context("perepareInterface() should", func() {
		var _ = It("return error if cannot get interface from pool", func() {
			readInterfaceConf = fakeReadInterfaceConfErr
			pi := &sriovPodInterface{
				log:  logrus.NewEntry(logrus.New()),
				pool: &fakePoolErr{},
			}
			_, _, err := pi.perepareInterface()
			Expect(err).To(HaveOccurred())
		})
	})
	var _ = Context("doSriovNetwork() should", func() {
		var _ = It("return error if cannot get netns", func() {
			getNS = fakeGetNSErr
			err := doSriovNetwork(&proto.AddRequest{}, &types.InterfaceInfo{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if get link by name", func() {
			getNS = fakeGetNS
			linkByName = fakeLinkByNameErr
			err := doSriovNetwork(&proto.AddRequest{}, &types.InterfaceInfo{InterfaceName: "dummyIf"})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot set link down", func() {
			getNS = fakeGetNS
			linkByName = fakeLinkByName
			linkSetDown = fakeLinkSetErr
			err := doSriovNetwork(&proto.AddRequest{}, &types.InterfaceInfo{InterfaceName: "dummyIf"})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot set MTU", func() {
			getNS = fakeGetNS
			linkByName = fakeLinkByName
			linkSetDown = fakeLinkSet
			linkSetMTU = fakeLinkSetValueErr
			err := doSriovNetwork(&proto.AddRequest{Settings: &proto.ContainerSettings{Mtu: 1500}}, &types.InterfaceInfo{InterfaceName: "dummyIf"})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot set NS fd", func() {
			getNS = fakeGetNS
			linkByName = fakeLinkByName
			linkSetDown = fakeLinkSet
			linkSetMTU = fakeLinkSetValue
			linkSetNsFd = fakeLinkSetValueErr
			err := doSriovNetwork(&proto.AddRequest{Settings: &proto.ContainerSettings{Mtu: 1500}}, &types.InterfaceInfo{InterfaceName: "dummyIf"})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot configure Sr-IOV namespace", func() {
			getNS = fakeGetNS
			linkByName = fakeLinkByName
			linkSetDown = fakeLinkSet
			linkSetMTU = fakeLinkSetValue
			linkSetNsFd = fakeLinkSetValue
			withNetNSPath = fakeWithNetNSPathErr
			err := doSriovNetwork(&proto.AddRequest{Settings: &proto.ContainerSettings{Mtu: 1500}}, &types.InterfaceInfo{InterfaceName: "dummyIf"})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error no error", func() {
			getNS = fakeGetNS
			linkByName = fakeLinkByName
			linkSetDown = fakeLinkSet
			linkSetMTU = fakeLinkSetValue
			linkSetNsFd = fakeLinkSetValue
			withNetNSPath = fakeWithNetNSPathSuccessful
			err := doSriovNetwork(&proto.AddRequest{Settings: &proto.ContainerSettings{Mtu: 1500}}, &types.InterfaceInfo{InterfaceName: "dummyIf"})
			Expect(err).ToNot(HaveOccurred())
		})
	})
	var _ = Context("configureSriovNamespace() should", func() {
		var _ = It("return error if cannot set link name", func() {
			withNetNSPath = fakeWithNetNSPath
			linkSetName = fakeLinkSetNameErr
			err := configureSriovNamespace(&proto.AddRequest{}, &fakeLink{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot get link by name", func() {
			withNetNSPath = fakeWithNetNSPath
			linkSetName = fakeLinkSetName
			linkByName = fakeLinkByNameErr
			err := configureSriovNamespace(&proto.AddRequest{}, &fakeLink{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot set link address", func() {
			withNetNSPath = fakeWithNetNSPath
			linkSetName = fakeLinkSetName
			linkByName = fakeLinkByName
			addrAdd = fakeAddrAddDelErr
			request := &proto.AddRequest{
				ContainerRoutes: []string{"192.168.0.0/24"},
				ContainerIps: []*proto.IPConfig{
					{
						Address: "192.168.0.2/24",
						Gateway: "192.168.0.1/24",
					},
				},
			}
			err := configureSriovNamespace(request, &fakeLink{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot set link up", func() {
			withNetNSPath = fakeWithNetNSPath
			linkSetName = fakeLinkSetName
			linkByName = fakeLinkByName
			addrAdd = fakeAddrAddDel
			linkSetUp = fakeLinkSetErr
			request := &proto.AddRequest{
				ContainerRoutes: []string{"192.168.0.0/24"},
				ContainerIps: []*proto.IPConfig{
					{
						Address: "192.168.0.2/24",
						Gateway: "192.168.0.1/24",
					},
				},
			}
			err := configureSriovNamespace(request, &fakeLink{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot setup pod route", func() {
			withNetNSPath = fakeWithNetNSPath
			linkSetName = fakeLinkSetName
			linkByName = fakeLinkByName
			addrAdd = fakeAddrAddDel
			linkSetUp = fakeLinkSet
			ipAddRoute = fakeIPAddRouteErr
			request := &proto.AddRequest{
				ContainerRoutes: []string{"192.168.0.0/24"},
				ContainerIps: []*proto.IPConfig{
					{
						Address: "192.168.0.2/24",
						Gateway: "192.168.0.1/24",
					},
				},
			}
			err := configureSriovNamespace(request, &fakeLink{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return no error", func() {
			withNetNSPath = fakeWithNetNSPath
			linkSetName = fakeLinkSetName
			linkByName = fakeLinkByName
			addrAdd = fakeAddrAddDel
			linkSetUp = fakeLinkSet
			ipAddRoute = fakeIPAddRoute
			request := &proto.AddRequest{
				ContainerRoutes: []string{"192.168.0.0/24"},
				ContainerIps: []*proto.IPConfig{
					{
						Address: "192.168.0.2/24",
						Gateway: "192.168.0.1/24",
					},
				},
			}
			err := configureSriovNamespace(request, &fakeLink{})
			Expect(err).ToNot(HaveOccurred())
		})
	})
	var _ = Context("configureIpvlanNamespace() should", func() {
		var _ = It("return error if cannot set link name", func() {
			linkSetName = fakeLinkSetNameErr
			_, _, err := configureIpvlanNamespace(&fakeNetNS{}, &netlink.IPVlan{}, &proto.AddRequest{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot get link by name", func() {
			linkSetName = fakeLinkSetName
			linkByName = fakeLinkByNameErr
			_, _, err := configureIpvlanNamespace(&fakeNetNS{}, &netlink.IPVlan{}, &proto.AddRequest{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if sysctl cannot set link address", func() {
			linkSetName = fakeLinkSetName
			linkByName = fakeLinkByName
			sysctlFunc = fakeSysctl
			addrAdd = fakeAddrAddDelErr
			request := &proto.AddRequest{
				ContainerIps: []*proto.IPConfig{
					{
						Address: "192.167.0.2/24",
						Gateway: "192.168.0.1/24",
					},
				},
			}
			_, _, err := configureIpvlanNamespace(&fakeNetNS{}, &netlink.IPVlan{}, request)
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if sysctl cannot set link up", func() {
			linkSetName = fakeLinkSetName
			linkByName = fakeLinkByName
			sysctlFunc = fakeSysctl
			addrAdd = fakeAddrAddDel
			linkSetUp = fakeLinkSetErr
			request := &proto.AddRequest{
				ContainerIps: []*proto.IPConfig{
					{
						Address: "192.167.0.2/24",
						Gateway: "192.168.0.1/24",
					},
				},
			}
			_, _, err := configureIpvlanNamespace(&fakeNetNS{}, &netlink.IPVlan{}, request)
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if sysctl cannot setup pod route", func() {
			linkSetName = fakeLinkSetName
			linkByName = fakeLinkByName
			sysctlFunc = fakeSysctl
			addrAdd = fakeAddrAddDel
			linkSetUp = fakeLinkSet
			ipAddRoute = fakeIPAddRouteErr
			request := &proto.AddRequest{
				ContainerIps: []*proto.IPConfig{
					{
						Address: "192.167.0.2/24",
						Gateway: "192.168.0.1/24",
					},
				},
				ContainerRoutes: []string{"192.168.0.0/24"},
			}
			_, _, err := configureIpvlanNamespace(&fakeNetNS{}, &netlink.IPVlan{}, request)
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if sysctl cannot list addresses", func() {
			linkSetName = fakeLinkSetName
			linkByName = fakeLinkByName
			sysctlFunc = fakeSysctl
			addrAdd = fakeAddrAddDel
			linkSetUp = fakeLinkSet
			ipAddRoute = fakeIPAddRoute
			addrList = fakeAddrListErr
			request := &proto.AddRequest{
				ContainerIps: []*proto.IPConfig{
					{
						Address: "192.167.0.2/24",
						Gateway: "192.168.0.1/24",
					},
				},
				ContainerRoutes: []string{"192.168.0.0/24"},
			}
			_, _, err := configureIpvlanNamespace(&fakeNetNS{}, &netlink.IPVlan{}, request)
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return no error", func() {
			linkSetName = fakeLinkSetName
			linkByName = fakeLinkByName
			sysctlFunc = fakeSysctl
			addrAdd = fakeAddrAddDel
			linkSetUp = fakeLinkSet
			ipAddRoute = fakeIPAddRoute
			addrList = fakeAddrList
			request := &proto.AddRequest{
				ContainerIps: []*proto.IPConfig{
					{
						Address: "192.167.0.2/24",
						Gateway: "192.168.0.1/24",
					},
				},
				ContainerRoutes: []string{"192.168.0.0/24"},
			}
			_, _, err := configureIpvlanNamespace(&fakeNetNS{}, &netlink.IPVlan{}, request)
			Expect(err).ToNot(HaveOccurred())
		})
	})
	var _ = Context("DoIpvlanNetwork() should", func() {
		var _ = It("return error if cannot get link by name", func() {
			linkByName = fakeLinkByNameErr
			_, err := DoIpvlanNetwork(&proto.AddRequest{}, "dummyIf", netlink.IPVLAN_MODE_L3)
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot get NS", func() {
			linkByName = fakeLinkByName
			getNS = fakeGetNSErr
			_, err := DoIpvlanNetwork(&proto.AddRequest{}, "dummyIf", netlink.IPVLAN_MODE_L3)
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot add link", func() {
			linkByName = fakeLinkByName
			getNS = fakeGetNS
			linkAdd = fakeLinkSetErr
			request := &proto.AddRequest{
				DesiredHostInterfaceName: "dummyDesired",
				Settings: &proto.ContainerSettings{
					Mtu: 0,
				},
			}
			_, err := DoIpvlanNetwork(request, "dummyIf", netlink.IPVLAN_MODE_L3)
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot configure namespace", func() {
			linkByName = fakeLinkByName
			getNS = fakeGetNS
			linkAdd = fakeLinkSet
			linkSetName = fakeLinkSetName
			sysctlFunc = fakeSysctl
			addrAdd = fakeAddrAddDel
			linkSetUp = fakeLinkSet
			ipAddRoute = fakeIPAddRoute
			addrList = fakeAddrListErr
			request := &proto.AddRequest{
				DesiredHostInterfaceName: "dummyDesired",
				Settings: &proto.ContainerSettings{
					Mtu: 0,
				},
				ContainerIps: []*proto.IPConfig{
					{
						Address: "192.167.0.2/24",
						Gateway: "192.168.0.1/24",
					},
				},
				ContainerRoutes: []string{"192.168.0.0/24"},
			}
			_, err := DoIpvlanNetwork(request, "dummyIf", netlink.IPVLAN_MODE_L3)
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot setup routing", func() {
			linkByName = fakeLinkByName
			getNS = fakeGetNS
			linkAdd = fakeLinkSet
			linkSetName = fakeLinkSetName
			sysctlFunc = fakeSysctl
			addrAdd = fakeAddrAddDel
			linkSetUp = fakeLinkSet
			ipAddRoute = fakeIPAddRoute
			addrList = fakeAddrList
			routeListFiltered = fakeRouteListFilteredErr
			request := &proto.AddRequest{
				DesiredHostInterfaceName: "dummyDesired",
				Settings: &proto.ContainerSettings{
					Mtu: 0,
				},
				ContainerIps: []*proto.IPConfig{
					{
						Address: "192.167.0.2/24",
						Gateway: "192.168.0.1/24",
					},
				},
				ContainerRoutes: []string{"192.168.0.0/24"},
			}
			_, err := DoIpvlanNetwork(request, "dummyIf", netlink.IPVLAN_MODE_L3)
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error no error", func() {
			linkByName = fakeLinkByName
			getNS = fakeGetNS
			linkAdd = fakeLinkSet
			linkSetName = fakeLinkSetName
			sysctlFunc = fakeSysctl
			addrAdd = fakeAddrAddDel
			linkSetUp = fakeLinkSet
			ipAddRoute = fakeIPAddRoute
			addrList = fakeAddrList
			routeListFiltered = fakeRouteListFilteredExisting
			routeAdd = fakeRouteHandle
			request := &proto.AddRequest{
				DesiredHostInterfaceName: "dummyDesired",
				Settings: &proto.ContainerSettings{
					Mtu: 0,
				},
				ContainerIps: []*proto.IPConfig{
					{
						Address: "192.167.0.2/24",
						Gateway: "192.168.0.1/24",
					},
				},
				ContainerRoutes: []string{"192.168.0.0/24"},
			}
			_, err := DoIpvlanNetwork(request, "dummyIf", netlink.IPVLAN_MODE_L3)
			Expect(err).ToNot(HaveOccurred())
		})
	})
	var _ = Context("setupRouting() should", func() {
		var _ = It("return error if cannot get link by name", func() {
			linkByName = fakeLinkByNameErr
			err := setupRouting([]netlink.Addr{})
			Expect(err).To(HaveOccurred())
		})
	})
	var _ = Context("ReleaseIpvlanNetwork() should", func() {
		var _ = It("return error if cannot configure NS", func() {
			withNetNSPath = fakeWithNetNSPathErr
			err := ReleaseIpvlanNetwork(&proto.DelRequest{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return no error is NS does not exist", func() {
			withNetNSPath = fakeWithNetNSPathErrNotExist
			err := ReleaseIpvlanNetwork(&proto.DelRequest{})
			Expect(err).ToNot(HaveOccurred())
		})
		var _ = It("return error if cannot configure NS", func() {
			withNetNSPath = fakeWithNetNSPathErr
			err := ReleaseIpvlanNetwork(&proto.DelRequest{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error if cannot delete link by name", func() {
			withNetNSPath = fakeWithNetNSPath
			linkByName = fakeLinkByName
			delLinkByName = fakeDelLinkByNameErr
			err := ReleaseIpvlanNetwork(&proto.DelRequest{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return no error", func() {
			withNetNSPath = fakeWithNetNSPath
			linkByName = fakeLinkByName
			delLinkByName = fakeDelLinkByName
			err := ReleaseIpvlanNetwork(&proto.DelRequest{})
			Expect(err).ToNot(HaveOccurred())
		})
	})
	var _ = Context("NewIpvlanPodInterface() should", func() {
		var _ = It("return new ipvlanPodInterface", func() {
			pi, err := NewIpvlanPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
			Expect(pi).ToNot(BeNil())
		})
	})
	var _ = Context("ReleasePodInterface() should", func() {
		var _ = It("return no error", func() {
			withNetNSPath = fakeWithNetNSPath
			linkByName = fakeLinkByName
			delLinkByName = fakeDelLinkByName
			pi, err := NewIpvlanPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
			err = pi.ReleasePodInterface(&proto.DelRequest{})
			Expect(err).ToNot(HaveOccurred())
		})
	})
	var _ = Context("ReleaseNetwork() should", func() {
		var _ = It("return no error", func() {
			withNetNSPath = fakeWithNetNSPath
			linkByName = fakeLinkByName
			delLinkByName = fakeDelLinkByName
			pi, err := NewIpvlanPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
			_, err = pi.ReleaseNetwork(context.TODO(), mockClient, &proto.DelRequest{})
			Expect(err).ToNot(HaveOccurred())
		})
	})
	var _ = Context("CreatePodInterface() should", func() {
		var _ = It("return error if cannot setup ipvlan network", func() {
			linkByName = fakeLinkByNameErr
			pi, err := NewIpvlanPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())

			_, err = pi.CreatePodInterface(&proto.AddRequest{})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return no error", func() {
			linkByName = fakeLinkByName
			getNS = fakeGetNS
			linkAdd = fakeLinkSet
			linkSetName = fakeLinkSetName
			sysctlFunc = fakeSysctl
			addrAdd = fakeAddrAddDel
			linkSetUp = fakeLinkSet
			ipAddRoute = fakeIPAddRoute
			addrList = fakeAddrList
			routeListFiltered = fakeRouteListFilteredExisting
			routeAdd = fakeRouteHandle
			request := &proto.AddRequest{
				DesiredHostInterfaceName: "dummyDesired",
				Settings: &proto.ContainerSettings{
					Mtu: 0,
				},
				ContainerIps: []*proto.IPConfig{
					{
						Address: "192.167.0.2/24",
						Gateway: "192.168.0.1/24",
					},
				},
				ContainerRoutes: []string{"192.168.0.0/24"},
			}
			pi, err := NewIpvlanPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())

			_, err = pi.CreatePodInterface(request)
			Expect(err).ToNot(HaveOccurred())
		})
	})
	var _ = Context("SetupNetwork() should", func() {
		var _ = It("return error if cannot create network", func() {
			pi, err := NewIpvlanPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
			gomock.InOrder(mockClient.EXPECT().CreateNetwork(gomock.Any(), gomock.Any()).Return(&proto.AddReply{Successful: false}, errors.New("Error")))
			_, err = pi.SetupNetwork(context.TODO(), mockClient, nil, &proto.AddRequest{DesiredHostInterfaceName: "dummyDesired"})
			Expect(err).To(HaveOccurred())
		})
		var _ = It("return error no error", func() {
			pi, err := NewIpvlanPodInterface(logrus.NewEntry(logrus.New()))
			Expect(err).ToNot(HaveOccurred())
			gomock.InOrder(mockClient.EXPECT().CreateNetwork(gomock.Any(), gomock.Any()).Return(&proto.AddReply{Successful: true}, nil))
			_, err = pi.SetupNetwork(context.TODO(), mockClient, nil, &proto.AddRequest{DesiredHostInterfaceName: "dummyDesired"})
			Expect(err).ToNot(HaveOccurred())
		})
	})
	var _ = Context("NewPodInterface() should", func() {
		var _ = It("not create interface if type is unsupported", func() {
			intf, _ := NewPodInterface("unsupported", logrus.NewEntry(logrus.New()))
			Expect(intf).To(BeNil())
		})
		var _ = It("create new ipvlan interface", func() {
			intf, _ := NewPodInterface(types.IpvlanPodInterface, logrus.NewEntry(logrus.New()))
			Expect(intf).ToNot(BeNil())
			_, ok := intf.(*ipvlanPodInterface)
			Expect(ok).To(BeTrue())
		})
		var _ = It("create new sriov interface", func() {
			intf, _ := NewPodInterface(types.SriovPodInterface, logrus.NewEntry(logrus.New()))
			Expect(intf).ToNot(BeNil())
			_, ok := intf.(*sriovPodInterface)
			Expect(ok).To(BeTrue())
		})
		var _ = It("create new tap interface", func() {
			intf, _ := NewPodInterface(types.TapInterface, logrus.NewEntry(logrus.New()))
			Expect(intf).ToNot(BeNil())
			_, ok := intf.(*tapPodInterface)
			Expect(ok).To(BeTrue())
		})
	})
	var _ = Context("tapPodInterface.setup() should", func() {
		var _ = It("return error if cannot get interface from the pool", func() {
			readInterfaceConf = fakeReadInterfaceConfErr
			pi := &tapPodInterface{
				pool: &fakePoolErr{},
				log:  logrus.NewEntry(logrus.New()),
			}
			err := pi.setup([]*types.InterfaceInfo{})
			Expect(err).To(HaveOccurred())
		})
	})
})

type fakeLink struct{}

func (fl *fakeLink) Attrs() *netlink.LinkAttrs {
	return &netlink.LinkAttrs{
		Index:        testIfIndex,
		HardwareAddr: net.HardwareAddr{},
	}
}

func (fl *fakeLink) Type() string {
	return ""
}

func fakeAddRoute(ipn *net.IPNet, gw net.IP, dev netlink.Link) error {
	return nil
}

func fakeAddRouteErr(ipn *net.IPNet, gw net.IP, dev netlink.Link) error {
	return errors.New("Fake error on AddRoute")
}

func fakeAddrAddDel(link netlink.Link, addr *netlink.Addr) error {
	return nil
}

func fakeAddrAddDelErr(link netlink.Link, addr *netlink.Addr) error {
	return errors.New("Fake error on AddrAdd/Del")
}

func fakeAddrList(link netlink.Link, family int) ([]netlink.Addr, error) {
	return []netlink.Addr{{IPNet: &net.IPNet{}}}, nil
}

func fakeAddrListWithResult(link netlink.Link, family int) ([]netlink.Addr, error) {
	return []netlink.Addr{{}}, nil
}

func fakeAddrListErr(link netlink.Link, family int) ([]netlink.Addr, error) {
	return nil, errors.New("Fake error on AddrList")
}

func fakeLinkByName(name string) (netlink.Link, error) {
	return &fakeLink{}, nil
}

func fakeLinkByNameErr(name string) (netlink.Link, error) {
	return nil, errors.New("Fake error on LinkByName")
}

func fakeLinkSet(link netlink.Link) error {
	return nil
}

func fakeLinkSetErr(link netlink.Link) error {
	return errors.New("Fake error on LinkSetUp/Down")
}

func fakeRouteListFilteredExisting(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error) {
	return []netlink.Route{{
		Dst:       &net.IPNet{IP: ipAddr, Mask: mask},
		LinkIndex: testIfIndex,
		Scope:     netlink.SCOPE_LINK,
	}}, nil
}

func fakeRouteListFiltereToBeDeleted(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error) {
	return []netlink.Route{{
		Dst:       &net.IPNet{IP: ipAddr, Mask: mask},
		LinkIndex: testIfIndex + 1,
		Scope:     netlink.SCOPE_LINK,
	}}, nil
}

func fakeRouteListFilteredErr(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error) {
	return nil, errors.New("Fake error on routeListFiltered")
}

func fakeRouteHandle(route *netlink.Route) error {
	return nil
}

func fakeRouteHandleErr(route *netlink.Route) error {
	return errors.New("Fake error on handling route add/del")
}

func fakeGetTapInterfacesErr(prefix string) ([]*types.InterfaceInfo, error) {
	return nil, errors.New("Fake error on getTapInterfaces")
}

func fakeGetTapInterfacesEmpty(prefix string) ([]*types.InterfaceInfo, error) {
	return []*types.InterfaceInfo{}, nil
}

func fakeGetTapInterfacesSingle(prefix string) ([]*types.InterfaceInfo, error) {
	return []*types.InterfaceInfo{{PciAddr: "0000:00:00.0", InterfaceName: "dummyIf0", VfID: 0, MacAddr: "00:00:00:00:00:00"}}, nil
}

func fakeGetTapInterfacesMultiple(prefix string) ([]*types.InterfaceInfo, error) {
	return []*types.InterfaceInfo{{PciAddr: "0000:00:00.0", InterfaceName: "dummyIf0", VfID: 0, MacAddr: "00:00:00:00:00:00"}, {PciAddr: "0000:00:00.1", InterfaceName: "dummyIf1", VfID: 0, MacAddr: "00:00:00:00:00:01"}}, nil
}

func fakeConfigureHostInterface(ifName string, ipnet *net.IPNet, interfaces []*types.InterfaceInfo, log *logrus.Entry) error {
	return nil
}

func fakeConfigureHostInterfaceErr(ifName string, ipnet *net.IPNet, interfaces []*types.InterfaceInfo, log *logrus.Entry) error {
	return errors.New("Fake error on getting configureHostInterface")
}

func fakeGetHostIPfromPodCIDR(log *logrus.Entry, ec *utils.EnvConfigurer) (*net.IPNet, error) {
	return &net.IPNet{}, nil
}

func fakeGetHostIPfromPodCIDRErr(log *logrus.Entry, ec *utils.EnvConfigurer) (*net.IPNet, error) {
	return nil, errors.New("Fake error on getting getHostIPfromPodCIDR")
}

func fakeConfigureRouting(link netlink.Link, log *logrus.Entry) error {
	return nil
}

func fakeConfigureRoutingErr(link netlink.Link, log *logrus.Entry) error {
	return errors.New("Fake error while configuring routing")
}

func fakeReleaseIPFromIPAM(ec *utils.EnvConfigurer, ipamExecDel utils.IpamExecDelFunc) error {
	return nil
}

func fakeReleaseIPFromIPAMErr(ec *utils.EnvConfigurer, ipamExecDel utils.IpamExecDelFunc) error {
	return errors.New("Fake error on ReleaseIPFromIPAM")
}

func fakeGetIPFromIPAM(ec *utils.EnvConfigurer, ipamExecAdd utils.IpamExecAddFunc) (*net.IPNet, error) {
	return &net.IPNet{}, nil
}

func fakeGetIPFromIPAMErr(ec *utils.EnvConfigurer, ipamExecAdd utils.IpamExecAddFunc) (*net.IPNet, error) {
	return nil, errors.New("Fake error on GetIPFromIPAM")
}

func fakeSetHostInterfaceInPodNetns(in *proto.AddRequest, res *types.InterfaceInfo) error {
	return nil
}

func fakeSetHostInterfaceInPodNetnsErr(in *proto.AddRequest, res *types.InterfaceInfo) error {
	return errors.New("Fake error on SetHostInterfaceInPodNetns")
}

func fakeSetHostInterfaceInPodNetnsErrInNs(in *proto.AddRequest, res *types.InterfaceInfo) error {
	return newNsError(errors.New("Fake error on SetHostInterfaceInPodNetns inside netns"))
}

func fakeSaveInterfaceConf(dataDir, refid, podIface string, conf *types.InterfaceInfo) error {
	return nil
}

func fakeSaveInterfaceConfErr(dataDir, refid, podIface string, conf *types.InterfaceInfo) error {
	return errors.New("Fake error on SaveInterfaceConf")
}

func fakeReadInterfaceConf(dataDir, refid, podIface string) (*types.InterfaceInfo, error) {
	return &types.InterfaceInfo{}, nil
}

func fakeReadInterfaceConfErr(dataDir, refid, podIface string) (*types.InterfaceInfo, error) {
	return nil, errors.New("Fake error on ReadInterfaceConf")
}

func fakeReadInterfaceConfNotExist(dataDir, refid, podIface string) (*types.InterfaceInfo, error) {
	return nil, os.ErrNotExist
}

func fakeMovePodInterfaceToHostNetns(netNSPath, interfaceName string, ifInfo *types.InterfaceInfo) error {
	return nil
}

func fakeMovePodInterfaceToHostNetnsErr(netNSPath, interfaceName string, ifInfo *types.InterfaceInfo) error {
	return errors.New("Fake error on movePodInterfaceToHostNetns")
}

func fakeWithNetNSPath(nspath string, toRun func(ns.NetNS) error) error {
	return toRun(globalTestNs)
}

func fakeWithNetNSPathSuccessful(nspath string, toRun func(ns.NetNS) error) error {
	return nil
}

func fakeWithNetNSPathErr(nspath string, toRun func(ns.NetNS) error) error {
	return errors.New("Error on WithNetNSPath")
}

func fakeWithNetNSPathErrNotExist(nspath string, toRun func(ns.NetNS) error) error {
	return ns.NSPathNotExistErr{}
}

type fakeNetNS struct{}

func (fns *fakeNetNS) Do(toRun func(ns.NetNS) error) error {
	return toRun(globalTestNs)
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

func fakeGetNS(nspath string) (ns.NetNS, error) {
	return &fakeNetNS{}, nil
}

func fakeGetNSErr(nspath string) (ns.NetNS, error) {
	return nil, errors.New("Fake error on GetNS")
}

func fakeLinkSetValue(link netlink.Link, value int) error {
	return nil
}

func fakeLinkSetValueErr(link netlink.Link, value int) error {
	return errors.New("Fake error on LinkSet")
}

func fakeLinkSetName(link netlink.Link, value string) error {
	return nil
}

func fakeLinkSetNameErr(link netlink.Link, value string) error {
	return errors.New("Fake error on LinkSetName")
}

func fakeIPAddRoute(ipn *net.IPNet, gw net.IP, dev netlink.Link) error {
	return nil
}

func fakeIPAddRouteErr(ipn *net.IPNet, gw net.IP, dev netlink.Link) error {
	return errors.New("Fake error on IPAddRoute")
}

func fakeGetCurrentNS() (ns.NetNS, error) {
	return &fakeNetNS{}, nil
}

func fakeGetCurrentNSErr() (ns.NetNS, error) {
	return nil, errors.New("Fake error on getCurrentNS")
}

func fakeGetVFList(pf string, prefix string) ([]*types.InterfaceInfo, error) {
	return []*types.InterfaceInfo{}, nil
}

func fakeGetVFListSingle(pf string, prefix string) ([]*types.InterfaceInfo, error) {
	return []*types.InterfaceInfo{{}}, nil
}

func fakeGetVFListMulti(pf string, prefix string) ([]*types.InterfaceInfo, error) {
	return []*types.InterfaceInfo{{}, {}}, nil
}

func fakeGetVFListErr(pf string, prefix string) ([]*types.InterfaceInfo, error) {
	return nil, errors.New("Fake error on getVFList")
}

type fakePoolErr struct{}

func (fp *fakePoolErr) Get() (*pool.Resource, error) {
	return nil, errors.New("Fake error on pool get")
}

func (fp *fakePoolErr) Release(res string) {}

func (fp *fakePoolErr) Save(path string) error {
	return nil
}

func fakeSysctl(name string, params ...string) (string, error) {
	return "", nil
}

func fakeDelLinkByName(name string) error {
	return nil
}

func fakeDelLinkByNameErr(name string) error {
	return errors.New("Fake error on delLinkByName")
}

func fakeSendSetupHostInterface(request *proto.SetupHostInterfaceRequest) error {
	return nil
}

func fakeSendSetupHostInterfaceErr(request *proto.SetupHostInterfaceRequest) error {
	return errors.New("Fake error on sendSetupHostInterface")
}

func fakeGrpcDial(target string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	return grpc.DialContext(context.TODO(), "", grpc.WithTransportCredentials(insecure.NewCredentials()))
}

func fakeGrpcDialErr(target string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	return nil, errors.New("Fake error on grpcDial")
}

func newFakeClient(cc *grpc.ClientConn) proto.InfraAgentClient {
	return mockClient
}

func fakeSetLinkAddress(link netlink.Link, containerIps []*proto.IPConfig) error {
	return nil
}

func fakeSetLinkAddressErr(link netlink.Link, containerIps []*proto.IPConfig) error {
	return errors.New("Fake error on setLinkAddress")
}
