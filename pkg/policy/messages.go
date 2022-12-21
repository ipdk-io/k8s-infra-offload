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

// COPIED FROM vpp-dataplane project

package policy

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"

	pb "github.com/gogo/protobuf/proto"
	"github.com/ipdk-io/k8s-infra-offload/proto"
)

func (s *PolicyServer) RecvMessage(conn net.Conn) (msg interface{}, err error) {
	buf := make([]byte, 8)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return
	}
	length := binary.LittleEndian.Uint64(buf)

	data := make([]byte, length)
	_, err = io.ReadFull(conn, data)
	if err != nil {
		return
	}

	envelope := proto.ToDataplane{}
	err = pb.Unmarshal(data, &envelope)
	if err != nil {
		return
	}
	s.log.WithField("envelope", envelope).Debug("Received message from dataplane.")

	msg = s.setMessage(&envelope)

	return
}

func (s *PolicyServer) setMessage(envelope *proto.ToDataplane) interface{} {
	switch payload := envelope.Payload.(type) {
	case *proto.ToDataplane_ConfigUpdate:
		return payload.ConfigUpdate
	case *proto.ToDataplane_InSync:
		return payload.InSync
	case *proto.ToDataplane_IpsetUpdate:
		return payload.IpsetUpdate
	case *proto.ToDataplane_IpsetDeltaUpdate:
		return payload.IpsetDeltaUpdate
	case *proto.ToDataplane_IpsetRemove:
		return payload.IpsetRemove
	case *proto.ToDataplane_ActivePolicyUpdate:
		return payload.ActivePolicyUpdate
	case *proto.ToDataplane_ActivePolicyRemove:
		return payload.ActivePolicyRemove
	case *proto.ToDataplane_ActiveProfileUpdate:
		return payload.ActiveProfileUpdate
	case *proto.ToDataplane_ActiveProfileRemove:
		return payload.ActiveProfileRemove
	case *proto.ToDataplane_HostEndpointUpdate:
		return payload.HostEndpointUpdate
	case *proto.ToDataplane_HostEndpointRemove:
		return payload.HostEndpointRemove
	case *proto.ToDataplane_WorkloadEndpointUpdate:
		return payload.WorkloadEndpointUpdate
	case *proto.ToDataplane_WorkloadEndpointRemove:
		return payload.WorkloadEndpointRemove
	case *proto.ToDataplane_HostMetadataUpdate:
		return payload.HostMetadataUpdate
	case *proto.ToDataplane_HostMetadataRemove:
		return payload.HostMetadataRemove
	case *proto.ToDataplane_IpamPoolUpdate:
		return payload.IpamPoolUpdate
	case *proto.ToDataplane_IpamPoolRemove:
		return payload.IpamPoolRemove
	case *proto.ToDataplane_ServiceAccountUpdate:
		return payload.ServiceAccountUpdate
	case *proto.ToDataplane_ServiceAccountRemove:
		return payload.ServiceAccountRemove
	case *proto.ToDataplane_NamespaceUpdate:
		return payload.NamespaceUpdate
	case *proto.ToDataplane_NamespaceRemove:
		return payload.NamespaceRemove
	case *proto.ToDataplane_RouteUpdate:
		return payload.RouteUpdate
	case *proto.ToDataplane_RouteRemove:
		return payload.RouteRemove
	case *proto.ToDataplane_VtepRemove:
		return payload.VtepRemove
	case *proto.ToDataplane_VtepUpdate:
		return payload.VtepUpdate
	case *proto.ToDataplane_WireguardEndpointUpdate:
		return payload.WireguardEndpointUpdate
	case *proto.ToDataplane_WireguardEndpointRemove:
		return payload.WireguardEndpointRemove
	case *proto.ToDataplane_GlobalBgpConfigUpdate:
		return payload.GlobalBgpConfigUpdate
	default:
		s.log.WithField("payload", payload).Warn("Ignoring unknown message from felix")
	}
	return nil
}

func (s *PolicyServer) SendMessage(conn net.Conn, msg interface{}) (err error) {
	s.log.Debugf("Writing msg (%v) to felix: %#v", s.nextSeqNumber, msg)
	// Wrap the payload message in an envelope so that protobuf takes care of deserialising
	// it as the correct type.
	envelope := &proto.FromDataplane{
		SequenceNumber: s.nextSeqNumber,
	}
	s.nextSeqNumber++
	s.setPayload(msg, envelope)
	data, err := pb.Marshal(envelope)

	if err != nil {
		s.log.WithError(err).WithField("msg", msg).Panic(
			"Failed to marshal data")
	}

	lengthBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(lengthBytes, uint64(len(data)))
	var messageBuf bytes.Buffer
	_, err = messageBuf.Write(lengthBytes)
	if err != nil {
		s.log.WithError(err).Panic("write to buffer failed")
	}
	_, err = messageBuf.Write(data)
	if err != nil {
		s.log.WithError(err).Panic("write to buffer failed")
	}
	for {
		_, err := messageBuf.WriteTo(conn)
		if err == io.ErrShortWrite {
			s.log.Warn("Short write to felix; buffer full?")
			continue
		}
		if err != nil {
			return err
		}
		s.log.Debug("Wrote message to felix")
		break
	}
	return nil
}

func (s *PolicyServer) setPayload(msg interface{}, envelope *proto.FromDataplane) {
	switch msg := msg.(type) {
	case *proto.ProcessStatusUpdate:
		envelope.Payload = &proto.FromDataplane_ProcessStatusUpdate{ProcessStatusUpdate: msg}
	case *proto.WorkloadEndpointStatusUpdate:
		envelope.Payload = &proto.FromDataplane_WorkloadEndpointStatusUpdate{WorkloadEndpointStatusUpdate: msg}
	case *proto.WorkloadEndpointStatusRemove:
		envelope.Payload = &proto.FromDataplane_WorkloadEndpointStatusRemove{WorkloadEndpointStatusRemove: msg}
	case *proto.HostEndpointStatusUpdate:
		envelope.Payload = &proto.FromDataplane_HostEndpointStatusUpdate{HostEndpointStatusUpdate: msg}
	case *proto.HostEndpointStatusRemove:
		envelope.Payload = &proto.FromDataplane_HostEndpointStatusRemove{HostEndpointStatusRemove: msg}
	case *proto.WireguardStatusUpdate:
		envelope.Payload = &proto.FromDataplane_WireguardStatusUpdate{WireguardStatusUpdate: msg}
	default:
		s.log.WithField("msg", msg).Panic("Unknown message type")
	}
}
