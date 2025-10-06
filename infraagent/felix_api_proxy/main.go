// Copyright (C) 2019 Cisco Systems Inc.
// Copyright (C) 2022 Intel Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/ipdk-io/k8s-infra-offload/pkg/types"
	"github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
)

const (
	connRetries    = 10
	connRetryDelay = time.Second
)

type dialFunc func(network string, address string) (net.Conn, error)

func main() {
	var t tomb.Tomb

	log := logrus.New()

	inFile, outFile, err := preparePipes(log, os.NewFile)
	if err != nil {
		log.Fatalf("Failed to setup connection to felix")
	}

	socket, err := connectToSocket(log, types.FelixDataplaneSocket, connRetries, connRetryDelay, net.Dial)
	if err != nil {
		log.Fatalf("Failed to setup connection to felix")
	}

	t.Go(func() error {
		return copyData(socket, inFile, "agent")
	})
	t.Go(func() error {
		return copyData(outFile, socket, "felix")
	})

	<-t.Dying()
	log.Info("Felix proxy exited")
}

func copyData(dst io.Writer, src io.Reader, destination string) error {
	_, _ = io.Copy(dst, src)
	return fmt.Errorf("copying to %s stopped", destination)
}

func preparePipes(log *logrus.Logger, createPipe func(fd uintptr, name string) *os.File) (*os.File, *os.File, error) {
	inFile := createPipe(3, "pipe1")
	outFile := createPipe(4, "pipe2")
	if inFile == nil || outFile == nil {
		return nil, nil, errors.New("Cannot open pipe FDs")
	}
	return inFile, outFile, nil
}

func connectToSocket(log *logrus.Logger, socketPath string, retries int, delay time.Duration, dialerFunction dialFunc) (net.Conn, error) {
	var socket net.Conn
	var err error
	for i := 1; i <= retries; i++ {
		socket, err = dialerFunction("unix", socketPath)
		if err == nil {
			break
		} else if i < retries {
			log.WithError(err).Warnf("Try %d: Cannot open socket to agent (unix://%s)", i, socketPath)
			time.Sleep(delay)
		} else {
			return nil, fmt.Errorf("Could not open socket to agent: %w", err)
		}
	}
	return socket, nil
}
