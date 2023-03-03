package healthserver

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"

	"github.com/ipdk-io/k8s-infra-offload/pkg/types"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/test/bufconn"
	"gopkg.in/tomb.v2"
)

const bufSize = 1024 * 1024

var (
	listener *bufconn.Listener
	gRPChs   *testHS
)

type testHS struct {
	res            []*grpc_health_v1.HealthCheckResponse
	sequenceNumber int
	srv            *grpc.Server
}

func (s *testHS) Check(context.Context, *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	if len(s.res) == 1 {
		return s.res[0], nil
	} else if s.sequenceNumber >= len(s.res) {
		return nil, errors.New("out of index")
	}
	retval := s.res[s.sequenceNumber]
	s.sequenceNumber++
	return retval, nil
}

func (s *testHS) Watch(*grpc_health_v1.HealthCheckRequest, grpc_health_v1.Health_WatchServer) error {
	return nil
}

func (s *testHS) setRes(response []*grpc_health_v1.HealthCheckResponse) {
	s.res = response
}

type inMemoryServer struct {
	listener *bufconn.Listener
	*http.Server
}

func newInMemoryServer(h http.Handler) *inMemoryServer {
	retval := &inMemoryServer{
		listener: bufconn.Listen(bufSize),
		Server:   &http.Server{Handler: h},
	}
	return retval
}

func (s *inMemoryServer) ListenAndServe() error {
	return s.Serve(s.listener)
}

func (s *inMemoryServer) newHttpClient() *http.Client {
	transport := &http.Transport{}
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return s.listener.Dial()
	}
	return &http.Client{Transport: transport}
}

func bufDialer(context.Context, string) (net.Conn, error) {
	return listener.Dial()
}

func TestHealthServer(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Health Server Test Suite")
}

var _ = BeforeSuite(func() {
	listener = bufconn.Listen(bufSize)
	grpcDial = func(target string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
		ctx := context.Background()
		return grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(bufDialer), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	}
	grpcDialForMgr = grpcDial
	gRPChs = &testHS{res: []*grpc_health_v1.HealthCheckResponse{{Status: grpc_health_v1.HealthCheckResponse_SERVING}}, srv: grpc.NewServer()}
	grpc_health_v1.RegisterHealthServer(gRPChs.srv, gRPChs)
	go func() {
		defer GinkgoRecover()
		err := gRPChs.srv.Serve(listener)
		Expect(err).ToNot(HaveOccurred())
	}()
})

var _ = AfterSuite(func() {
	gRPChs.srv.GracefulStop()
	err := listener.Close()
	Expect(err).ToNot(HaveOccurred())
})

var _ = Describe("HealthServer", func() {
	var _ = Context("NewHealthCheckServer() should", func() {
		var _ = It("create new HealthServer instance without error", func() {
			srv, err := NewHealthCheckServer(logrus.NewEntry(logrus.StandardLogger()))
			Expect(err).ToNot(HaveOccurred())
			Expect(srv).ToNot(BeNil())
			Expect(srv.(*healtServer).srv).ToNot(BeNil())
		})
	})

	var _ = Context("GetName() should ", func() {
		var _ = It("return health-server", func() {
			srv, err := NewHealthCheckServer(logrus.NewEntry(logrus.StandardLogger()))
			Expect(err).ToNot(HaveOccurred())
			Expect(srv).ToNot(BeNil())
			Expect(srv.(*healtServer).srv).ToNot(BeNil())
			Expect(srv.GetName()).Should(Equal("health-server"))
		})
	})

	var _ = Context("getCheck() should", func() {
		var _ = It("return HTTP_200 for check request", func() {
			var t tomb.Tomb
			hs := &healtServer{log: logrus.NewEntry(logrus.StandardLogger())}
			mux := http.NewServeMux()
			mux.HandleFunc("/check", getCheck(hs))
			hs.srv = newInMemoryServer(mux)
			t.Go(func() error {
				defer GinkgoRecover()
				err := hs.Start(&t)
				Expect(err).ToNot(HaveOccurred())
				return nil
			})
			// fake services running
			types.ServiceServerStatus = types.ServerStatusOK
			c := hs.srv.(*inMemoryServer).newHttpClient()
			res, err := c.Get("http://in-memory-server/check")
			Expect(err).ToNot(HaveOccurred())
			Expect(res).ToNot(BeNil())
			Expect(res.StatusCode).To(Equal(http.StatusOK))
			res.Body.Close()

			t.Kill(errors.New("stop"))
			err = t.Wait()
			Expect(err).To(HaveOccurred())
		})

		var _ = It("return HTTP_500 if policy server not running", func() {
			var t tomb.Tomb
			hs := &healtServer{log: logrus.NewEntry(logrus.StandardLogger())}
			mux := http.NewServeMux()
			mux.HandleFunc("/check", getCheck(hs))
			hs.srv = newInMemoryServer(mux)
			t.Go(func() error {
				defer GinkgoRecover()
				err := hs.Start(&t)
				Expect(err).ToNot(HaveOccurred())
				return nil
			})
			// fake services stopped
			types.ServiceServerStatus = types.ServerStatusStopped
			c := hs.srv.(*inMemoryServer).newHttpClient()
			res, err := c.Get("http://in-memory-server/check")
			Expect(err).To(BeNil())
			Expect(res).ToNot(BeNil())
			Expect(res.StatusCode).To(Equal(http.StatusInternalServerError))
			res.Body.Close()

			t.Kill(errors.New("stop"))
			err = t.Wait()
			Expect(err).To(HaveOccurred())
		})

		var _ = It("return HTTP_500 if gRPC server not running", func() {
			var t tomb.Tomb
			hs := &healtServer{log: logrus.NewEntry(logrus.StandardLogger())}
			mux := http.NewServeMux()
			mux.HandleFunc("/check", getCheck(hs))
			hs.srv = newInMemoryServer(mux)
			t.Go(func() error {
				defer GinkgoRecover()
				err := hs.Start(&t)
				Expect(err).ToNot(HaveOccurred())
				return nil
			})
			// fake services running
			types.ServiceServerStatus = types.ServerStatusOK
			// grpc return error
			response := []*grpc_health_v1.HealthCheckResponse{{Status: grpc_health_v1.HealthCheckResponse_NOT_SERVING}}
			gRPChs.setRes(response)
			c := hs.srv.(*inMemoryServer).newHttpClient()
			res, err := c.Get("http://in-memory-server/check")
			Expect(err).To(BeNil())
			Expect(res).ToNot(BeNil())
			Expect(res.StatusCode).To(Equal(http.StatusInternalServerError))
			res.Body.Close()

			t.Kill(errors.New("stop"))
			err = t.Wait()
			Expect(err).To(HaveOccurred())
		})

		var _ = It("return HTTP_500 if one of gRPC servers not running", func() {
			var t tomb.Tomb
			hs := &healtServer{log: logrus.NewEntry(logrus.StandardLogger())}
			mux := http.NewServeMux()
			mux.HandleFunc("/check", getCheck(hs))
			hs.srv = newInMemoryServer(mux)
			t.Go(func() error {
				defer GinkgoRecover()
				err := hs.Start(&t)
				Expect(err).ToNot(HaveOccurred())
				return nil
			})
			// fake services running
			types.ServiceServerStatus = types.ServerStatusOK
			// grpc return error
			response := []*grpc_health_v1.HealthCheckResponse{{Status: grpc_health_v1.HealthCheckResponse_SERVING}, {Status: grpc_health_v1.HealthCheckResponse_NOT_SERVING}}
			gRPChs.setRes(response)
			c := hs.srv.(*inMemoryServer).newHttpClient()
			res, err := c.Get("http://in-memory-server/check")
			Expect(err).To(BeNil())
			Expect(res).ToNot(BeNil())
			Expect(res.StatusCode).To(Equal(http.StatusInternalServerError))
			res.Body.Close()

			t.Kill(errors.New("stop"))
			err = t.Wait()
			Expect(err).To(HaveOccurred())
		})

	})
})
