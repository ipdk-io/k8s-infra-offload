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

package config

import (
	"fmt"

	"github.com/ipdk-io/k8s-infra-offload/pkg/types"
	"github.com/ipdk-io/k8s-infra-offload/pkg/utils"
	"github.com/spf13/viper"
)

func ReadConfig(conf *Configuration, cfgFileName string) {
	// Set the file name of the configurations file
	viper.SetConfigName(cfgFileName)

	// Set the path to look for the configurations file
	viper.AddConfigPath("/etc/infra")

	// Enable VIPER to read Environment Variables
	viper.AutomaticEnv()

	viper.SetConfigType("yaml")

	viper.SetDefault("InterfaceType", types.CDQInterface)
	viper.SetDefault("Infrap4dGrpcServer.Addr", "localhost:9559")
	viper.SetDefault("Infrap4dGrpcServer.conn", "mtls")
	viper.SetDefault("Infrap4dGrpcServer.client-cert", types.ManagerDefaultClientCert)
	viper.SetDefault("Infrap4dGrpcServer.client-key", types.ManagerDefaultClientKey)
	viper.SetDefault("Infrap4dGrpcServer.ca-cert", types.ManagerDefaultCACert)

	viper.SetDefault("Infrap4dGnmiServer.Addr", "localhost:9339")
	viper.SetDefault("Infrap4dGnmiServer.conn", "mtls")
	viper.SetDefault("Infrap4dGnmiServer.client-cert", types.ManagerDefaultClientCert)
	viper.SetDefault("Infrap4dGnmiServer.client-key", types.ManagerDefaultClientKey)
	viper.SetDefault("Infrap4dGnmiServer.ca-cert", types.ManagerDefaultCACert)

	viper.SetDefault("InfraManager.Addr", "localhost:50002")
	viper.SetDefault("InfraManager.conn", "mtls")
	viper.SetDefault("InfraManager.server-cert", types.ManagerDefaultServerCert)
	viper.SetDefault("InfraManager.server-key", types.ManagerDefaultServerKey)
	viper.SetDefault("InfraManager.client-cert", types.ManagerDefaultClientCert)
	viper.SetDefault("InfraManager.client-key", types.ManagerDefaultClientKey)
	viper.SetDefault("InfraManager.ca-cert", types.ManagerDefaultCACert)
	viper.SetDefault("InfraManager.ciphersuites", utils.DefaultCipherSuites())

	viper.SetDefault("LogLevel", "Debug")
	viper.SetDefault("Infrap4dTimeout", types.Infrap4dTimeout)

	if err := viper.ReadInConfig(); err != nil {
		fmt.Printf("Error reading config file, %s", err)
	}

	err := viper.Unmarshal(conf)
	if err != nil {
		fmt.Printf("Unable to decode into struct, %v", err)
	}

	conf.P4InfoPath = types.P4InfoPath
	conf.P4BinPath = types.P4BinPath

	// Reading variables without using the model
	fmt.Println("Infrap4d GRPC Server Addr:\t", viper.GetString("Infrap4dGrpcServer.Addr"))
	fmt.Println("Infrap4d GRPC Server Con:\t", viper.GetString("Infrap4dGrpcServer.Conn"))
	fmt.Println("Infrap4dGNMI Server Addr:\t", viper.GetString("Infrap4dGnmiServer.Addr"))
	fmt.Println("Infrap4dGNMI Server Con:\t", viper.GetString("Infrap4dGnmiServer.Conn"))
	fmt.Println("InfraManager Addr:\t", viper.GetString("InfraManager.Addr"))
	fmt.Println("InfraManager Con:\t", viper.GetString("InfraManager.Conn"))
}
