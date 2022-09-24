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

package pb

import (
	"log"

	"golang.org/x/net/context"
)

type Server struct {
}

var pipelineconfig *ForwardingPipelineConfig = new(ForwardingPipelineConfig)
var entities []*Entity
var singleentity *Entity

func (s *Server) Write(ctx context.Context, in *WriteRequest) (*WriteResponse, error) {
	log.Printf("Write message body from client: %v", in)
	for _, value := range in.Updates {
		singleentity = value.Entity
		entities = append(entities, singleentity)
	}
	return &WriteResponse{}, nil
}

func (s *Server) Read(in1 *ReadRequest, in2 P4Runtime_ReadServer) error {
	log.Printf("Read message body from client: %v", in1)
	in2.Send(&ReadResponse{Entities: entities})
	return nil
}

func (s *Server) SetForwardingPipelineConfig(ctx context.Context, in *SetForwardingPipelineConfigRequest) (*SetForwardingPipelineConfigResponse, error) {
	pipelineconfig = in.GetConfig()
	log.Printf("SetForwardingPipelineConfigRequest  message body from client: %v", in)
	return &SetForwardingPipelineConfigResponse{}, nil
}

func (s *Server) GetForwardingPipelineConfig(ctx context.Context, in *GetForwardingPipelineConfigRequest) (*GetForwardingPipelineConfigResponse, error) {
	log.Printf("GetForwardingPipelineConfigRequest  message body from client: %v", in)
	return &GetForwardingPipelineConfigResponse{
		Config: pipelineconfig,
	}, nil
}
func (s *Server) StreamChannel(in P4Runtime_StreamChannelServer) error {
	log.Printf("StreamChannel message body from client: %v", in)
	return nil
}

func (s *Server) Capabilities(ctx context.Context, in *CapabilitiesRequest) (*CapabilitiesResponse, error) {
	log.Printf("CapabilitiesRequest  message body from client: %v", in)
	return &CapabilitiesResponse{
		P4RuntimeApiVersion: "1",
	}, nil
}
