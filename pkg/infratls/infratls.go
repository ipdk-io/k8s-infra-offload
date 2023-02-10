package infratls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"github.com/ipdk-io/k8s-infra-offload/pkg/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

type AuthType int
type Service int
type Conn int
type CAType int

const (
	UnknownAuth AuthType = iota
	Insecure
	ServerSideTLS
	MutualTLS
)
const (
	UnknownService Service = iota
	InfraAgent
	InfraManager
)
const (
	UnknownConn Conn = iota
	Client
	Server
)
const (
	UnknownCA CAType = iota
	ClientCA
	ServerCA
)

type ServerParams struct {
	KeepAlive bool
	AuthType  AuthType
	Service   Service
	ConClient Service
}

func GetAuthType(auth string) AuthType {
	auth = strings.ToLower(auth)
	switch auth {
	case "unknownauth":
		return UnknownAuth
	case "insecure":
		return Insecure
	case "serversidetls":
		return ServerSideTLS
	case "mutualtls":
		return MutualTLS
	default:
		return UnknownAuth
	}
}

func getServiceString(service Service) string {
	switch service {
	case UnknownService:
		return "UnknownService"
	case InfraManager:
		return "InfraManager"
	case InfraAgent:
		return "InfraAgent"
	default:
		return "Unknown"
	}
}
func getCAString(c CAType) string {
	switch c {
	case UnknownCA:
		return "UnknownConn"
	case ServerCA:
		return "Server"
	case ClientCA:
		return "Client"
	default:
		return "Unknown"
	}
}

// delete
func createCertPool(cert []byte) (*x509.CertPool, error) {
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(cert) {
		err := errors.New("Failed to append cert to the pool")
		return nil, err
	}
	return certPool, nil
}

func loadCA(caType CAType) ([]byte, error) {
	var ca string

	switch caType {
	case ServerCA:
		ca = types.InfraServerCA
		return ioutil.ReadFile(ca)
	case ClientCA:
		ca = types.InfraClientCA
		return ioutil.ReadFile(ca)
	default:
		err := fmt.Errorf("Unknown CA type %s",
			getCAString(caType))
		return nil, err
	}
}

func getCertFile(service Service, c Conn) string {
	switch service {
	case InfraManager:
		switch c {
		case Server:
			return types.InfraManagerServerCert
		case Client:
			return types.InfraManagerClientCert
		default:
			return ""
		}
	case InfraAgent:
		switch c {
		case Server:
			return types.InfraAgentServerCert
		case Client:
			return types.InfraAgentClientCert
		default:
			return ""
		}
	default:
		return ""
	}
}

func getKeyFile(service Service, c Conn) string {
	switch service {
	case InfraManager:
		switch c {
		case Server:
			return types.InfraManagerServerKey
		case Client:
			return types.InfraManagerClientKey
		default:
			return ""
		}
	case InfraAgent:
		switch c {
		case Server:
			return types.InfraAgentServerKey
		case Client:
			return types.InfraAgentClientKey
		default:
			return ""
		}
	default:
		return ""
	}

}

func loadCert(service Service, c Conn) (tls.Certificate, error) {
	certFile := getCertFile(service, c)
	if len(certFile) == 0 {
		err := fmt.Errorf("Cert file not found for %s", getServiceString(service))
		return tls.Certificate{}, err
	}
	keyFile := getKeyFile(service, c)
	if len(certFile) == 0 {
		err := fmt.Errorf("Key file not found for %s", getServiceString(service))
		return tls.Certificate{}, err
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	return cert, err
}

func NewGrpcServer(params ServerParams) (*grpc.Server, error) {
	opt := []grpc.ServerOption{}
	if params.KeepAlive {
		kp := grpc.KeepaliveParams(keepalive.ServerParameters{MaxConnectionAge: time.Duration(time.Second * 10),
			MaxConnectionAgeGrace: time.Duration(time.Second * 30)})
		opt = append(opt, kp)

	}

	switch params.AuthType {
	case Insecure:

	case ServerSideTLS:
		serverCert, err := loadCert(params.Service, Server)
		if err != nil {
			return nil, err
		}

		config := &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientAuth:   tls.NoClientCert,
		}

		creds := credentials.NewTLS(config)
		opt = append(opt, grpc.Creds(creds))

	case MutualTLS:
		serverCert, err := loadCert(params.Service, Server)
		if err != nil {
			return nil, err
		}

		clientCA, err := loadCA(ClientCA)
		if err != nil {
			return nil, err
		}

		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(clientCA) {
			err := errors.New("Failed to append cert to the pool")
			return nil, err
		}
		config := &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    certPool,
		}

		creds := credentials.NewTLS(config)
		opt = append(opt, grpc.Creds(creds))
	default:
		err := fmt.Errorf("Invalid authentication type")
		return nil, err
	}

	return grpc.NewServer(opt...), nil
}

// delete
func getServiceType(target string) Service {
	switch target {
	case fmt.Sprintf("%s:%s", types.InfraManagerAddr, types.InfraManagerPort):
		return InfraManager
	case fmt.Sprintf("%s:%s", types.InfraAgentAddr, types.InfraAgentPort):
		return InfraAgent
	default:
		return UnknownService
	}
}

func GrpcDial(target string, authType AuthType, c Service) (*grpc.ClientConn, error) {
	var creds grpc.DialOption

	switch authType {
	case Insecure:
		creds = grpc.WithTransportCredentials(insecure.NewCredentials())
	case ServerSideTLS:
		serverCA, err := loadCA(ServerCA)
		if err != nil {
			return nil, err
		}

		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(serverCA) {
			err := errors.New("Failed to append cert to the pool")
			return nil, err
		}
		config := &tls.Config{
			RootCAs: certPool,
		}

		creds = grpc.WithTransportCredentials(credentials.NewTLS(config))
	case MutualTLS:
		clientCert, err := loadCert(c, Client)
		if err != nil {
			return nil, err
		}

		serverCA, err := loadCA(ServerCA)
		if err != nil {
			return nil, err
		}

		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(serverCA) {
			err := errors.New("Failed to append cert to the pool")
			return nil, err
		}
		config := &tls.Config{
			Certificates: []tls.Certificate{clientCert},
			RootCAs:      certPool,
		}

		creds = grpc.WithTransportCredentials(credentials.NewTLS(config))
	default:
		return nil, errors.New("Unknown authentication type")
	}

	return grpc.Dial(target, creds)
}
