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

//go:build es2k

package test

import (
	"context"
	"flag"
	"net"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	"github.com/antoninbas/p4runtime-go-client/pkg/client"
	"github.com/antoninbas/p4runtime-go-client/pkg/signals"
	p4 "github.com/ipdk-io/k8s-infra-offload/pkg/inframanager/p4"
	p4_v1 "github.com/p4lang/p4runtime/go/p4/v1"
)

var (
	ipAddress      = [3]string{"169.254.1.1", "10.10.10.1", "10.10.10.2"}
	tpa            = "172.254.1.1"
	defaultAddress = "localhost:9559"
)

var (
	port    = [3]uint16{26, 27, 28}
	modPtr  = [3]uint32{1, 2, 3}
	tpaPort = (uint16)(25)
)

var (
	macAddress = [3]string{"9e:07:ec:11:50:d0", "00:09:00:08:c5:50", "00:0a:00:09:c5:50"}
)

func Ipv4ToPortTableT(ctx context.Context, p4RtC *client.Client) error {
	for i := 0; i < 3; i++ {
		entry1 := p4RtC.NewTableEntry(
			"k8s_dp_control.ipv4_to_port_table_tx",
			map[string]client.MatchInterface{
				"hdrs.ipv4[meta.common.depth].dst_ip": &client.ExactMatch{
					Value: p4.Pack32BinaryIP4(ipAddress[i]),
				},
			},
			p4RtC.NewTableActionDirect("k8s_dp_control.set_dest_mac_vport", [][]byte{p4.ToBytes(port[i]), p4.ToBytes(modPtr[i])}),
			nil,
		)
		if err := p4RtC.InsertTableEntry(ctx, entry1); err != nil {
			log.Errorf("Cannot insert entry in 'ipv4_to_port_table': %v", err)
			return err
		}
		log.Infof("Inserted entry in 'ipv4_to_port_table TX'")

		entry2 := p4RtC.NewTableEntry(
			"k8s_dp_control.ipv4_to_port_table_rx",
			map[string]client.MatchInterface{
				"hdrs.ipv4[meta.common.depth].dst_ip": &client.ExactMatch{
					Value: p4.Pack32BinaryIP4(ipAddress[i]),
				},
			},
			p4RtC.NewTableActionDirect(
				"k8s_dp_control.set_dest_vport",
				[][]byte{p4.ToBytes(port[i])}),
			nil,
		)

		if err := p4RtC.InsertTableEntry(ctx, entry2); err != nil {
			log.Errorf("Failed to add entry in ipv4_to_port rx table: %v", err)
			return err
		}
		log.Infof("Inserted entry in 'ipv4_to_port_table RX'")
	}

	return nil
}

func ArptToPortTableT(ctx context.Context, p4RtC *client.Client) error {
	entryAdd := p4RtC.NewTableEntry(
		"k8s_dp_control.arp_to_port_table",
		map[string]client.MatchInterface{
			"hdrs.arp.tpa": &client.ExactMatch{
				Value: p4.Pack32BinaryIP4(tpa),
			},
		},
		p4RtC.NewTableActionDirect("k8s_dp_control.set_dest_vport", [][]byte{p4.ToBytes(tpaPort)}),
		nil,
	)

	if err := p4RtC.InsertTableEntry(ctx, entryAdd); err != nil {
		log.Errorf("Cannot insert entry into arp_to_port_table table, ip: %s, port: %d, err: %v",
			tpa, tpaPort, err)
		return err
	}
	log.Infof("Inserted entry in 'ArptToPortTable' ip: %s, port: %d", tpa, tpaPort)

	return nil
}

func GWMacModTableT(ctx context.Context, p4RtC *client.Client) error {

	dmac, _ := net.ParseMAC(macAddress[0])

	entry := p4RtC.NewTableEntry(
		"k8s_dp_control.pod_gateway_mac_mod_table",
		map[string]client.MatchInterface{
			"meta.common.mod_blob_ptr": &client.ExactMatch{
				Value: p4.ToBytes(modPtr[0]),
			},
		},
		p4RtC.NewTableActionDirect("k8s_dp_control.update_src_dst_mac", [][]byte{dmac}),
		nil,
	)

	if err := p4RtC.InsertTableEntry(ctx, entry); err != nil {
		log.Errorf("Failed to add entry in pod_gateway_mac_mod table: %v", err)
		return err
	}
	log.Infof("Inserted entry in 'GWMacModTable'")
	return nil
}

func InsertCniRulesT(ctx context.Context, p4RtC *client.Client, services bool) error {

	_ = services
	err := ArptToPortTableT(ctx, p4RtC)
	if err != nil {
		return err
	}

	err = Ipv4ToPortTableT(ctx, p4RtC)
	if err != nil {
		return err
	}

	err = GWMacModTableT(ctx, p4RtC)
	if err != nil {
		return err
	}

	return nil
}

func TestCni() {

	var addr string
	flag.StringVar(&addr, "addr", defaultAddress, "P4Runtime server socket")
	var deviceID uint64
	flag.Uint64Var(&deviceID, "device-id", 1, "Device id")

	ctx := context.Background()

	p4InfoPath, err := filepath.Abs("./k8s_dp/p4Info.txt")
	if err != nil {
		log.Fatalf("Failed to get absolute representation of path %s",
			p4InfoPath)
	}

	p4BinPath, err := filepath.Abs("./k8s_dp/k8s_dp.pb.bin")
	if err != nil {
		log.Fatalf("Failed to get absolute representation of path %s",
			p4BinPath)
	}

	if p4BinPath == "" || p4InfoPath == "" {
		log.Fatalf("Missing .bin or p4Info")
	}

	log.Infof("Connecting to server at %s , deviceID %v", addr, deviceID)
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

	//p4RtC := client.NewClient(c, deviceID, &electionID)
	p4RtC := client.NewClient(c, 1, &electionID)
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
	if _, err := p4RtC.SetFwdPipe(ctx, p4BinPath, p4InfoPath, 0); err != nil {
		log.Fatalf("Error when setting forwarding pipe: %v", err)
	}

	log.Info("installing the entries to the table")
	if err := InsertCniRulesT(ctx, p4RtC, true); err != nil {
		log.Fatalf("Error when installing entry %v", err)
	}

	log.Info("Do Ctrl-C to quit")
	<-stopCh
	log.Info("Stopping client")
}
