// Copyright (c) 2023 Intel Corporation.  All Rights Reserved.
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

package utils

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
	"sync"
	"time"

	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

type ConnType int
type Service int
type Conn int

const (
	UnknownConn ConnType = iota
	Insecure
	TLS
	MTLS
)
const (
	UnknownService Service = iota
	InfraAgent
	InfraManager
	Infrap4dGrpcServer
	Infrap4dGnmiServer
)
const (
	UnknownMod Conn = iota
	Client
	Server
)

type ServerParams struct {
	KeepAlive bool
	ConnType  ConnType
	ConClient Service
}

var onceMap sync.Once
var CipherMap map[string]uint16

func CreateCipherMap() {
	onceMap.Do(func() {
		ciphers := tls.CipherSuites()
		ciphers = append(ciphers, tls.InsecureCipherSuites()...)
		CipherMap = map[string]uint16{}

		for _, c := range ciphers {
			CipherMap[c.Name] = c.ID
		}
	})
}

func DefaultCipherSuites() []string {
	return []string{
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_AES_256_GCM_SHA384",
	}
}

func ValidCiphers(ciphers []string) bool {
	CreateCipherMap()
	for _, c := range ciphers {
		_, ok := CipherMap[c]
		if !ok {
			return false
		}
	}
	return true
}

func ConvertCiphers(ciphers []string) ([]uint16, error) {
	if len(ciphers) == 0 {
		err := errors.New("Empty cipher list")
		return []uint16{}, err
	}

	cc := []uint16{}
	for _, c := range ciphers {
		cipher, ok := CipherMap[c]
		if !ok {
			err := fmt.Errorf("Unknown cipher %s", c)
			return []uint16{}, err
		}
		cc = append(cc, cipher)

	}
	return cc, nil
}

// GetClientCredentials returns gRPC client credential based on user provided configuration.
// if "--insecure=true" it will provide insecure.NewCredentials
// if "--insecure=false" && "--mtls=true" it will provide mTLS credentials
// otherwise only server side validation with CA added in client CA pool
func GetClientCredentials() (credentials.TransportCredentials, error) {
	if viper.GetBool("insecure") {
		return insecure.NewCredentials(), nil
	}

	if viper.GetBool("mtls") {
		return getClientMTLSCredentials()
	} else {
		return getClientTLSCredentials()
	}
}

// getClientMTLSCredentials returns grpc mTLS credetials with client cert and key added
func getClientMTLSCredentials() (credentials.TransportCredentials, error) {
	clientCert := viper.GetString("clientCert")
	clientKey := viper.GetString("clientKey")
	caCert := viper.GetString("caCert")

	certificate, err := tls.LoadX509KeyPair(clientCert, clientKey)
	if err != nil {
		return nil, fmt.Errorf("loading client certificate failed: %s" + err.Error())
	}

	ca, err := ioutil.ReadFile(caCert)
	if err != nil {
		return nil, fmt.Errorf("loading ca cert failed: %s", err.Error())
	}

	capool := x509.NewCertPool()
	if !capool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("invalid CA file: %s", caCert)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		RootCAs:      capool,
	}

	return credentials.NewTLS(tlsConfig), nil
}

// getClientTLSCredentials retuns credentials for for client with only CA added to CA pool
func getClientTLSCredentials() (credentials.TransportCredentials, error) {

	caCert := viper.GetString("caCert")

	ca, err := ioutil.ReadFile(caCert)
	if err != nil {
		return nil, fmt.Errorf("loading ca cert failed: %s", err.Error())
	}

	capool := x509.NewCertPool()
	if !capool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("invalid CA file: %s", caCert)
	}

	tlsConfig := &tls.Config{
		RootCAs: capool,
	}

	return credentials.NewTLS(tlsConfig), nil
}

func GetConnType(conn string) ConnType {
	conn = strings.ToLower(conn)
	switch conn {
	case "insecure":
		return Insecure
	case "tls":
		return TLS
	case "mtls":
		return MTLS
	default:
		return UnknownConn
	}
}

func getServiceString(service Service) string {
	switch service {
	case InfraManager:
		return "InfraManager"
	case InfraAgent:
		return "InfraAgent"
	case Infrap4dGnmiServer:
		return "Infrap4dGnmiServer"
	case Infrap4dGrpcServer:
		return "Infrap4dGrpcServer"
	default:
		return "UnknownService"
	}
}
func getConnString(c Conn) string {
	switch c {
	case Server:
		return "Server"
	case Client:
		return "Client"
	default:
		return "Unknown"
	}
}

func loadCA(s Service) ([]byte, error) {
	var ca string

	switch s {
	case InfraAgent, InfraManager:
		/*
			The CA for infraagent and inframanager is same.
		*/
		ca = viper.GetString("InfraManager.caCert")
		return ioutil.ReadFile(ca)
	case Infrap4dGnmiServer:
		ca = viper.GetString("Infrap4dGnmiServer.caCert")
		return ioutil.ReadFile(ca)
	case Infrap4dGrpcServer:
		ca = viper.GetString("Infrap4dGrpcServer.caCert")
		return ioutil.ReadFile(ca)
	default:
		err := fmt.Errorf("No CA for service %s",
			getServiceString(s))
		return nil, err
	}
}

func getCertFile(c Conn) string {
	switch c {
	case Server:
		return viper.GetString("InfraManager.serverCert")
	case Client:
		return viper.GetString("InfraManager.clientCert")
	default:
		return ""
	}
}

func getKeyFile(c Conn) string {
	switch c {
	case Server:
		return viper.GetString("InfraManager.serverKey")
	case Client:
		return viper.GetString("InfraManager.clientKey")
	default:
		return ""
	}
}

func loadMgrCert(c Conn) (tls.Certificate, error) {
	certFile := getCertFile(c)
	if len(certFile) == 0 {
		err := fmt.Errorf("Inframanager %s cert file not found.", getConnString(c))
		return tls.Certificate{}, err
	}
	keyFile := getKeyFile(c)
	if len(certFile) == 0 {
		err := fmt.Errorf("Inframanager %s key file not found.", getConnString(c))
		return tls.Certificate{}, err
	}
	return tls.LoadX509KeyPair(certFile, keyFile)
}

func NewGrpcServer(params ServerParams) (*grpc.Server, error) {
	opt := []grpc.ServerOption{}
	if params.KeepAlive {
		kp := grpc.KeepaliveParams(keepalive.ServerParameters{MaxConnectionAge: time.Duration(time.Second * 10),
			MaxConnectionAgeGrace: time.Duration(time.Second * 30)})
		opt = append(opt, kp)

	}

	switch params.ConnType {
	case Insecure:

	case TLS:
		serverCert, err := loadMgrCert(Server)
		if err != nil {
			return nil, err
		}

		ciphers := viper.GetStringSlice("InfraManager.ciphersuites")
		ciphersuites, err := ConvertCiphers(ciphers)
		if err != nil {
			return nil, err
		}

		config := &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientAuth:   tls.NoClientCert,
			CipherSuites: ciphersuites,
		}

		creds := credentials.NewTLS(config)
		opt = append(opt, grpc.Creds(creds))

	case MTLS:
		serverCert, err := loadMgrCert(Server)
		if err != nil {
			return nil, err
		}

		clientCA, err := loadCA(params.ConClient)
		if err != nil {
			return nil, err
		}

		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(clientCA) {
			err := errors.New("Failed to append cert to the pool")
			return nil, err
		}

		ciphers := viper.GetStringSlice("InfraManager.ciphersuites")
		ciphersuites, err := ConvertCiphers(ciphers)
		if err != nil {
			return nil, err
		}

		config := &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    certPool,
			CipherSuites: ciphersuites,
		}

		creds := credentials.NewTLS(config)
		opt = append(opt, grpc.Creds(creds))
	default:
		err := fmt.Errorf("Invalid authentication type")
		return nil, err
	}

	return grpc.NewServer(opt...), nil
}

func GrpcDial(target string, connType ConnType, s Service) (*grpc.ClientConn, error) {
	var creds grpc.DialOption

	switch connType {
	case Insecure:
		creds = grpc.WithTransportCredentials(insecure.NewCredentials())
	case TLS:
		serverCA, err := loadCA(s)
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
	case MTLS:
		/*
			Load inframanager's client cert
		*/
		clientCert, err := loadMgrCert(Client)
		if err != nil {
			return nil, err
		}

		serverCA, err := loadCA(s)
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
