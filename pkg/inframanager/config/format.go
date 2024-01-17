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

import "time"

// Configurations exported
type Configuration struct {
	Infrap4dGrpcServer ServerConf  `yaml:"Infrap4dGrpcServer"`
	Infrap4dGnmiServer ServerConf  `yaml:"Infrap4dGnmiServer"`
	InfraManager       ManagerConf `yaml:"InfraManager"`
	InterfaceType      string      `yaml:"InterfaceType"`
	NodeIP             string
	LogLevel           string
	P4InfoPath         string
	P4BinPath          string
	DeviceId           uint64
	Infrap4dTimeout    time.Duration
	StopCh             <-chan struct{}
}

// ServerConfigurations exported
type ServerConf struct {
	Addr       string `mapstructure:"addr"`
	Conn       string `mapstructure:"conn"`
	ClientCert string `mapstructure:"client-cert"`
	ClientKey  string `mapstructure:"client-key"`
	CACert     string `mapstructure:"ca-cert"`
}
type ManagerConf struct {
	Addr         string   `mapstructure:"addr"`
	ArpMac       string   `mapstructure:"arp-mac"`
	Conn         string   `mapstructure:"conn"`
	ServerCert   string   `mapstructure:"server-cert"`
	ServerKey    string   `mapstructure:"server-key"`
	CACert       string   `mapstructure:"ca-cert"`
	CipherSuites []string `mapstructure:"ciphersuites"`
}
