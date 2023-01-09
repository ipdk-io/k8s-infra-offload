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

package utils

import (
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
)

type checkGrpcServerStatusType func(target string, log *logrus.Entry, grpcDial grpcDialType) (bool, error)

type grpcWatcher struct {
	sleepDuration time.Duration
	timeout       time.Duration
	target        string
	dialFunc      grpcDialType
	checkHealth   checkGrpcServerStatusType
	done          chan bool
	quit          chan bool
	errors        chan error
	log           *logrus.Entry
}

// NewGrpcWatcher returns new gRPC watcher
func NewGrpcWatcher(timeout, sleepDuration time.Duration, target string, dialFunc grpcDialType, checkHealth checkGrpcServerStatusType) *grpcWatcher {
	done := make(chan bool)
	quit := make(chan bool)
	errors := make(chan error)
	return &grpcWatcher{
		sleepDuration: sleepDuration,
		timeout:       timeout,
		target:        target,
		dialFunc:      dialFunc,
		checkHealth:   checkHealth,
		done:          done,
		quit:          quit,
		errors:        errors,
		log:           logrus.NewEntry(logrus.New()),
	}
}

func (gw *grpcWatcher) handleEvents() {
	for {
		select {
		case <-gw.quit:
			gw.errors <- fmt.Errorf("quit signal received")
			return
		default:
			if isServing, _ := gw.checkHealth(gw.target, gw.log, gw.dialFunc); isServing {
				gw.done <- true
				gw.errors <- nil
				return
			}
			time.Sleep(gw.sleepDuration)
		}
	}
}

func (gw *grpcWatcher) initialCheck() bool {
	status, _ := gw.checkHealth(gw.target, gw.log, gw.dialFunc)
	return status
}

func (gw *grpcWatcher) getChannels() (chan bool, chan bool, chan error) {
	return gw.done, gw.quit, gw.errors
}

func (gw *grpcWatcher) getTimeout() time.Duration {
	return gw.timeout
}

func (gw *grpcWatcher) addWatchedResources() error {
	return nil
}

func (gw *grpcWatcher) close() error {
	return nil
}
