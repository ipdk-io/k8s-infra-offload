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

package bfconfig

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"

	"github.com/golang/protobuf/proto"
	pb "github.com/ipdk-io/k8s-infra-offload/inframanager/pb"
	log "github.com/sirupsen/logrus"
)

const (
	filePath = "lb_demo.json"
)

func getConfig(in []byte) (*pb.P4RuntimeConfig, error) {
	conf := &pb.P4RuntimeConfig{}
	if err := json.Unmarshal(in, conf); err != nil {
		log.WithError(err).Error("cannot unmarshal json")
		return nil, err
	}
	return conf, nil
}

func getBfPipelineConfig(in *pb.P4RuntimeConfig) (*pb.BfPipelineConfig, error) {
	bfConfig := &pb.BfPipelineConfig{}
	if len(in.P4Devices) != 1 {
		return nil, errors.New("stratum only supports single devices")
	}
	if len(in.P4Devices[0].P4Programs) != 1 {
		return nil, errors.New("stratum only supports single P4 program")
	}

	bfConfig.P4Name = in.P4Devices[0].P4Programs[0].ProgramName
	path := in.P4Devices[0].P4Programs[0].BfrtConfig
	bfrtBytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.WithError(err).Error("cannot read file ", path)
		return nil, errors.New("failed to read bfrt json file")
	}
	bfConfig.BfruntimeInfo = bfrtBytes
	for _, p := range in.P4Devices[0].P4Programs[0].P4Pipelines {
		profile := &pb.BfPipelineConfig_Profile{
			ProfileName: p.P4PipelineName,
			PipeScope:   p.PipeScope,
		}

		contextBytes, err := ioutil.ReadFile(p.Context)
		if err != nil {
			// return or continue? log error for now
			log.WithError(err).Errorf("cannot read file %s",
				p.Context)
			return nil, errors.New("failed to read context json file")
		}
		profile.Context = contextBytes
		configBytes, err := ioutil.ReadFile(p.Config)
		if err != nil {
			// return or continue? log error for now
			log.WithError(err).Errorf("cannot read bin %s",
				p.Config)
			return nil, errors.New("failed to read bin file")
		}
		profile.Binary = configBytes
		bfConfig.Profiles = append(bfConfig.Profiles, profile)
	}
	return bfConfig, nil
}

func GenBfPipelineConfig(filePath string) (err error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		log.WithError(err).Errorf("cannot read file %s", filePath)
		panic(err)
	}

	conf, err := getConfig(data)
	if err != nil {
		log.WithError(err).Error("cannot get config")
		panic(err)
	}
	log.Infof("Parsed config %+v", conf)
	bfConfig, err := getBfPipelineConfig(conf)
	if err != nil {
		log.WithError(err).Error("cannot read BF config")
		panic(err)
	}
	out, err := proto.Marshal(bfConfig)
	if err != nil {
		log.Fatalln("Failed to encode p4 prog proto bin:", err)
	}
	if err := ioutil.WriteFile("example.txt", out, 0644); err != nil {
		log.Fatalln("Failed to the proto bin file:", err)
	}

	return err
}
