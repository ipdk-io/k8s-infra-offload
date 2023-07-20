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

package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/ipdk-io/k8s-infra-offload/pkg/types"

	"github.com/ipdk-io/k8s-infra-offload/pkg/utils"
	pb "github.com/ipdk-io/k8s-infra-offload/proto"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

var (
	grpcDial            = grpc.Dial
	getCredentialFunc   = utils.GetClientCredentials
	newInfraAgentClient = pb.NewInfraAgentClient
)

type ServiceHandler struct {
	log *logrus.Entry
}

func NewNatServiceHandler(log *logrus.Entry) *ServiceHandler {
	return &ServiceHandler{log: log}
}

func (s *ServiceHandler) dialManager() (pb.InfraAgentClient, *grpc.ClientConn, error) {
	managerAddr := fmt.Sprintf("%s:%s", types.InfraManagerAddr, types.InfraManagerPort)
	s.log.Info("dialer using manager address: ", managerAddr)
	credentials, err := getCredentialFunc()
	if err != nil {
		return nil, nil, fmt.Errorf("error getting gRPC client credentials to connect to backend: %s", err.Error())
	}
	conn, err := grpcDial(managerAddr, grpc.WithTransportCredentials(credentials))
	if err != nil {
		s.log.Errorf("unable to dial Infra Manager. err %v", err)
		return nil, nil, err
	}
	return newInfraAgentClient(conn), conn, nil
}

func (s *ServiceHandler) NatTranslationAdd(translation *pb.NatTranslation) error {
	s.log.Infof("NatTranslationAdd endpoint %v", translation)
	c, conn, err := s.dialManager()
	if err != nil {
		return err
	}
	defer conn.Close()
	reply, err := c.NatTranslationAdd(context.TODO(), translation)
	if err != nil {
		s.log.Errorf("Error calling  infra manager NatTranslationAdd serivce: %v", err)
		return err
	}
	if reply != nil && !reply.Successful {
		return errors.New(reply.ErrorMessage)
	}
	return nil
}

func (s *ServiceHandler) SetSnatAddress(ip string) error {
	s.log.Info("SetSnatAddress")
	c, conn, err := s.dialManager()
	if err != nil {
		return err
	}
	defer conn.Close()
	reply, err := c.SetSnatAddress(context.TODO(), &pb.SetSnatAddressRequest{SnatIpv4: ip, SnatIpv6: ""})
	if err != nil {
		return err
	}
	if !reply.Successful {
		return errors.New(reply.ErrorMessage)
	}
	return nil
}

func (s *ServiceHandler) AddDelSnatPrefix(ip string, isAdd bool) error {
	s.log.Info("AddDelSnatPrefix")
	c, conn, err := s.dialManager()
	if err != nil {
		return err
	}
	defer conn.Close()
	reply, err := c.AddDelSnatPrefix(context.TODO(), &pb.AddDelSnatPrefixRequest{IsAdd: isAdd, Prefix: ip})
	if err != nil {
		return err
	}
	if !reply.Successful {
		return errors.New(reply.ErrorMessage)
	}
	return nil
}

func (s *ServiceHandler) NatTranslationDelete(translation *pb.NatTranslation) error {
	s.log.Infof("NatTranslationDelete %v", translation)
	c, conn, err := s.dialManager()
	if err != nil {
		return err
	}
	defer conn.Close()
	reply, err := c.NatTranslationDelete(context.TODO(), translation)
	if err != nil {
		return err
	}
	if !reply.Successful {
		return errors.New(reply.ErrorMessage)
	}
	return nil
}
