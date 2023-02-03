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

package agent

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/ipdk-io/k8s-infra-offload/pkg/infraagent"
	"github.com/ipdk-io/k8s-infra-offload/pkg/infratls"
	"github.com/ipdk-io/k8s-infra-offload/pkg/types"
	"github.com/ipdk-io/k8s-infra-offload/pkg/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	configFilePath  = "/etc/infra/"
	intfFlagHelpMsg = "master interface name. If not defined Infra Agent will attempt to discover it."
)

var config struct {
	cfgFile          string
	interfaceType    string
	inframgrAuthType string
	interfaceName    string
	tapPrefix        string
}

var rootCmd = &cobra.Command{
	Use:   types.InfraAgentCLIName,
	Short: "Infra Agent is daemon that exposes a calico CNI gRPC backend for Intel MEV",
	Long: `
Infra Agent is daemon that exposes a calico CNI gRPC backend for networking offload to Infrastructure components.
It off-loads K8s dataplane to Infrastructure components.
`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		return validateConfigs()
	},
	Run: func(_ *cobra.Command, _ []string) {
		interfaceType := viper.GetString("interfaceType")
		ifName := viper.GetString("interface")
		config.inframgrAuthType = viper.GetString("inframgrAuthType")
		//config.inframgrAuthType = infratls.GetAuthType(authType)
		cfg, err := utils.GetK8sConfig()
		if err != nil {
			exitWithError(err, 2)
		}

		client, err := utils.GetK8sClient(cfg)
		if err != nil {
			exitWithError(err, 3)
		}
		agent, err := infraagent.NewAgent(interfaceType, ifName,
			infratls.GetAuthType(config.inframgrAuthType),
			types.InfraAgentLogDir, client)
		if err != nil {
			exitWithError(err, 4)
		}
		agent.Run()
	},
}

func exitWithError(err error, exitCode int) {
	fmt.Fprintf(os.Stderr, "There was an error while executing %s: '%s'\n", types.InfraAgentCLIName, err)
	os.Exit(exitCode)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		exitWithError(err, 1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	intfTypeOpts := newFlagOpts([]string{types.SriovPodInterface, types.IpvlanPodInterface, types.TapInterface}, types.SriovPodInterface)
	rootCmd.PersistentFlags().Var(intfTypeOpts, "interfaceType", "Pod Interface type (sriov|ipvlan|tap)")
	rootCmd.PersistentFlags().StringVar(&config.inframgrAuthType, "auth", "serversidetls", "Inframanager authentication type(insecure|serversidetls|mutualtls)")
	rootCmd.PersistentFlags().StringVar(&config.interfaceName, "interface", "", intfFlagHelpMsg)
	rootCmd.PersistentFlags().StringVar(&config.cfgFile, "config", "/etc/infra/infraagent.yaml", "config file")
	rootCmd.PersistentFlags().StringVar(&config.tapPrefix, "tapPrefix", types.TapInterfacePrefix, "Host TAP interface prefix for TAP interface type")
	if err := viper.BindPFlag("interfaceType", rootCmd.PersistentFlags().Lookup("interfaceType")); err != nil {
		fmt.Fprintf(os.Stderr, "There was an error while binding flags '%s'", err)
		os.Exit(1)
	}
	if err := viper.BindPFlag("auth", rootCmd.PersistentFlags().Lookup("auth")); err != nil {
		fmt.Fprintf(os.Stderr, "There was an error while binding flags '%s'", err)
		os.Exit(1)
	}
	if err := viper.BindPFlag("interface", rootCmd.PersistentFlags().Lookup("interface")); err != nil {
		fmt.Fprintf(os.Stderr, "There was an error while binding flags '%s'", err)
		os.Exit(1)
	}
	if err := viper.BindPFlag("tapPrefix", rootCmd.PersistentFlags().Lookup("tapPrefix")); err != nil {
		fmt.Fprintf(os.Stderr, "There was an error while binding flags '%s'", err)
		os.Exit(1)
	}
}

func initConfig() {
	// Load global config
	if config.cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(config.cfgFile)
	} else {
		// Search config in default location
		viper.AddConfigPath(configFilePath)
		viper.SetConfigType("yaml")
		viper.SetConfigName("infraagent.yaml")
	}

	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}

	// Load node-specific config
	if nodeName, err := utils.GetNodeName(); err == nil {
		types.NodeName = nodeName
		nodeConfig := fmt.Sprintf("%s.%s", types.NodeName, "yaml")

		// Check if config file exists and, if so, merge it with 'gobal' config
		nodeConfigPath := filepath.Join(configFilePath, nodeConfig)
		if _, err = os.Stat(nodeConfigPath); err == nil {
			viper.AddConfigPath(configFilePath)
			viper.SetConfigType("yaml")
			viper.SetConfigName(nodeConfig)
			if err = viper.MergeInConfig(); err == nil {
				fmt.Println("Using config file:", viper.ConfigFileUsed())
			} else {
				fmt.Fprintf(os.Stderr, "Unable to merge node-specific config: %s\n", err.Error())
			}
		}
	} else {
		fmt.Fprintf(os.Stderr, "Cannot determine node's name: %s\n", err.Error())
	}
}

// validate all configs in viper
func validateConfigs() error {
	var err error
	// validate interface type
	interfaceType := viper.GetString("interfaceType")
	if newErr := newFlagOpts([]string{types.SriovPodInterface, types.IpvlanPodInterface, types.TapInterface}, types.SriovPodInterface).Set(interfaceType); newErr != nil {
		err = fmt.Errorf("error validating interfaceType: %w", newErr)
	}

	inframgrAuthType := viper.GetString("inframgrAuthType")
	if infratls.GetAuthType(inframgrAuthType) == infratls.UnknownAuth {
		err = fmt.Errorf("Invalid authentication type for communicating with inframanager: %v",
			inframgrAuthType)
	}
	// When validating other configs wrap add error msgs in one and then return it at the end.
	// For example:
	//
	// anotherParam := viper.GetString("anotherParam")
	// if newErr := validate("anotherParam"); newErr != nil {
	// 	err = fmt.Errorf("%s;\nerror validating anotherField: %s", err, newErr)
	// }

	return err
}
