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

package main

import (
	"io"
	"net"
	"os"
	"path"
	"time"

	"github.com/ipdk-io/k8s-infra-offload/pkg/utils"
	"github.com/mdlayher/arp"
	log "github.com/sirupsen/logrus"
)

const (
	logDir = "/var/log"
)

func logInit() {
	logFilename := path.Join(logDir, path.Base(os.Args[0])+".log")
	verifiedFileName, err := utils.VerifiedFilePath(logFilename, logDir)
	if err != nil {
		panic(err)
	}

	logFile, err := os.OpenFile(verifiedFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}

	log.SetOutput(logFile)
	log.SetLevel(log.DebugLevel)
	log.SetReportCaller(true)
	log.SetFormatter(&log.TextFormatter{
		PadLevelText:     true,
		QuoteEmptyFields: true,
	})
}

func runARPProxy(client *arp.Client, ifi *net.Interface) {
	log.Info("ARP Proxy started!")
	// Handle ARP requests
	for {
		pkt, _, err := client.Read()
		if err != nil {
			if err == io.EOF {
				log.Error("EOF")
				break
			}
			log.Fatalf("Error processing ARP requests: %s", err)
		}
		log.Debugf("Received new packet for IP %s", pkt.TargetIP)

		// Ignore ARP replies
		if pkt.Operation != arp.OperationRequest {
			log.Debugf("Not an ARP request")
			continue
		} else {
			log.Debugf("Received an ARP request")
		}

		log.Debugf("Request: who-has %s?  tell %s (%s)", pkt.TargetIP, pkt.SenderIP, pkt.SenderHardwareAddr)

		// Send ARP reply
		log.Debugf("  Reply: %s is-at %s", pkt.TargetIP, ifi.HardwareAddr)
		if err := client.Reply(pkt, ifi.HardwareAddr, pkt.TargetIP); err != nil {
			log.Fatal(err)
		}
	}
}

func main() {
	var ifaceName string

	logInit()

	log.Info("Starting ARP Proxy")

	// Read the interface name to bind to
	ifaceName = os.Getenv("ARP_PROXY_IF")

	if len(ifaceName) == 0 {
		log.Fatalf("Can't start ARP Proxy! Set environment variable ARP_PROXY_IF to the name of interface to bind to.")
	}

	// Ensure valid interface name
	ifi, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Debugf("Interface %s not found. Waiting for the interface to be up. (Error msg: %s)", ifaceName, err)
	}
	for err != nil {
		time.Sleep(100 * time.Millisecond)
		ifi, err = net.InterfaceByName(ifaceName)
	}

	// Create ARP Proxy that listens for ARP requests on the above interface
	client, err := arp.Dial(ifi)
	if err != nil {
		log.Debugf("Waiting for IP address to be assigned. (Error msg: %s)", err)
	}
	for err != nil {
		time.Sleep(100 * time.Millisecond)
		client, err = arp.Dial(ifi)
	}
	log.Infof("Interface %s found with valid IP address. Ready to start ARP Proxy.", ifaceName)

	// Run ARP Proxy
	runARPProxy(client, ifi)
}
