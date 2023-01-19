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

	"github.com/spf13/viper"
)

func ReadConfig(conf *Configuration, cfgFileName string) {
	// Set the file name of the configurations file
	viper.SetConfigName(cfgFileName)

	// Set the path to look for the configurations file
	viper.AddConfigPath(".")

	// Enable VIPER to read Environment Variables
	viper.AutomaticEnv()

	viper.SetConfigType("yaml")

	if err := viper.ReadInConfig(); err != nil {
		fmt.Printf("Error reading config file, %s", err)
	}

	err := viper.Unmarshal(conf)
	if err != nil {
		fmt.Printf("Unable to decode into struct, %v", err)
	}

	// Reading variables without using the model
	fmt.Println("gRPC Server Addr:\t", viper.GetString("GrpcServer.Addr"))
	fmt.Println("gNMI Server Addr:\t", viper.GetString("GnmiServer.Addr"))
	fmt.Println("Log Level is set to :\t", viper.GetString("LogLevel"))
}
