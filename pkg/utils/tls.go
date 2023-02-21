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
	"fmt"
	"io/ioutil"

	"github.com/spf13/viper"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

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
	clientCert := viper.GetString("client-cert")
	clientKey := viper.GetString("client-key")
	caCert := viper.GetString("ca-cert")

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

	caCert := viper.GetString("ca-cert")

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
