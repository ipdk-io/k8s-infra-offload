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

package test

import (
	"context"
	"flag"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	p4_v1 "github.com/p4lang/p4runtime/go/p4/v1"

	"github.com/antoninbas/p4runtime-go-client/pkg/client"
	"github.com/antoninbas/p4runtime-go-client/pkg/signals"
)

var (
	ipAddress = [2]string{"10.10.10.1", "10.10.10.2"}
)

var (
	port = [2]uint32{0, 1}
)

var (
	macAddress = [2]string{"00:09:00:08:c5:50", "00:0a:00:09:c5:50"}
)

func insertIpv4ToPortTableEntry(ctx context.Context, p4RtC *client.Client) error {
	for i := 0; i < 2; i++ {
		entry1 := p4RtC.NewTableEntry(
			"k8s_dp_control.ipv4_to_port_table",
			map[string]client.MatchInterface{
				"hdr.arp.tpa": &client.LpmMatch{
					Value: Pack32BinaryIP4(ipAddress[i]),
					PLen:  int32(32),
				},
			},
			p4RtC.NewTableActionDirect("k8s_dp_control.set_dest_vport", [][]byte{valueToBytes(port[i])}),
			nil,
		)
		if err := p4RtC.InsertTableEntry(ctx, entry1); err != nil {
			log.Errorf("Cannot insert entry in 'ipv4_to_port_table': %v", err)
		}
	}

	return nil
}

func CniAddTest() {
	ctx := context.Background()

	p4InfoPath, _ := filepath.Abs("k8s_dp/p4Info.txt")
	p4BinPath, _ := filepath.Abs("k8s_dp/k8s_dp.pb.bin")

	var addr string
	flag.StringVar(&addr, "addr", defaultAddr, "P4Runtime server socket")
	var deviceID uint64
	flag.Uint64Var(&deviceID, "device-id", defaultDeviceID, "Device id")
	var binPath string
	flag.StringVar(&binPath, "bin", p4BinPath, "Path to P4 bin")
	var infoPath string
	flag.StringVar(&infoPath, "p4Info", p4InfoPath, "Path to p4Info")

	flag.Parse()

	if binPath == "" || infoPath == "" {
		log.Fatalf("Missing .bin or p4Info")
	}

	log.Infof("Connecting to server at %s", addr)
	conn, err := grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("Cannot connect to server: %v", err)
	}
	defer conn.Close()

	c := p4_v1.NewP4RuntimeClient(conn)
	resp, err := c.Capabilities(ctx, &p4_v1.CapabilitiesRequest{})
	if err != nil {
		log.Fatalf("Error in Capabilities RPC: %v", err)
	}
	log.Infof("P4Runtime server version is %s", resp.P4RuntimeApiVersion)

	stopCh := signals.RegisterSignalHandlers()

	electionID := p4_v1.Uint128{High: 0, Low: 1}

	p4RtC := client.NewClient(c, deviceID, &electionID)
	arbitrationCh := make(chan bool)
	go p4RtC.Run(stopCh, arbitrationCh, nil)

	waitCh := make(chan struct{})

	go func() {
		sent := false
		for isPrimary := range arbitrationCh {
			if isPrimary {
				log.Infof("We are the primary client!")
				if !sent {
					waitCh <- struct{}{}
					sent = true
				}
			} else {
				log.Infof("We are not the primary client!")
			}
		}
	}()

	func() {
		timeout := 5 * time.Second
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		select {
		case <-ctx.Done():
			log.Fatalf("Could not become the primary client within %v", timeout)
		case <-waitCh:
		}
	}()

	log.Info("Setting forwarding pipe")
	if _, err := p4RtC.SetFwdPipe(ctx, binPath, infoPath, 0); err != nil {
		log.Fatalf("Error when setting forwarding pipe: %v", err)
	}

	log.Info("installing the entries to the table")
	if err := insertIpv4ToPortTableEntry(ctx, p4RtC); err != nil {
		log.Fatalf("Error when installing entry %v", err)
	}

	log.Info("Do Ctrl-C to quit")
	<-stopCh
	log.Info("Stopping client")
}
