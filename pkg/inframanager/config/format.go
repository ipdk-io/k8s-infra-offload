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

// Configurations exported
type Configuration struct {
	Infrap4dGrpcServer ServerConf  `yaml:"Infrap4dGrpcServer,omitempty"`
	Infrap4dGnmiServer ServerConf  `yaml:"Infrap4dGnmiServer,omitempty"`
	InfraManager       ManagerConf `yaml:"InfraManager,omitempty"`
	InterfaceType      string      `yaml:"InterfaceType,omitempty"`
	NodeIP             string      `yaml:"NodeIP,omitempty"`
	LogLevel           string      `yaml:"LogLevel,omitempty"`
	P4InfoPath         string      `yaml:"P4InfoPath,omitempty"`
	P4BinPath          string      `yaml:"P4BinPath,omitempty"`
	DeviceId           uint64      `yaml:"DeviceID,omitempty"`
	DBTicker           uint32      `yaml:"DBTicker,omitempty"`
}

// ServerConfigurations exported
type ServerConf struct {
	Addr       string `yaml:"addr,omitempty"`
	Conn       string `yaml:"conn,omitempty"`
	ClientCert string `yaml:"client-cert,omitempty"`
	ClientKey  string `yaml:"client-key,omitempty"`
	CACert     string `yaml:"ca-cert,omitempty"`
}
type ManagerConf struct {
	Addr         string   `yaml:"addr,omitempty"`
	ArpMac       string   `yaml:"arp-mac,omitempty"`
	Conn         string   `yaml:"conn,omitempty"`
	ServerCert   string   `yaml:"server-cert,omitempty"`
	ServerKey    string   `yaml:"server-key,omitempty"`
	CACert       string   `yaml:"ca-cert,omitempty"`
	CipherSuites []string `yaml:"ciphersuites,flow,omitempty"`
}
