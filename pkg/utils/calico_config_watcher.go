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
	"os"
	"path"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

// calicoWatcher can be used to wait for calico file
type calicoWatcher struct {
	timeout    time.Duration
	configPath string
	done       chan bool
	quit       chan bool
	errors     chan error
	fsWatcher  *fsnotify.Watcher
}

// NewCalicoWatcher returns new watcher for Calico's config file
func NewCalicoWatcher(timeout time.Duration, configPath string, newFsWatcher func() (*fsnotify.Watcher, error)) (*calicoWatcher, error) {
	done := make(chan bool)
	quit := make(chan bool)
	errors := make(chan error)
	fsWatcher, err := newFsWatcher()
	if err != nil {
		return nil, err
	}
	return &calicoWatcher{
		timeout:    timeout,
		configPath: configPath,
		done:       done,
		quit:       quit,
		errors:     errors,
		fsWatcher:  fsWatcher,
	}, nil
}

func (cw *calicoWatcher) initialCheck() bool {
	if _, err := os.Stat(cw.configPath); err == nil {
		return true
	}
	return false
}

func (cw *calicoWatcher) handleEvents() {
	for {
		select {
		case event, ok := <-cw.fsWatcher.Events:
			if !ok {
				cw.done <- false
				cw.errors <- fmt.Errorf(event.String())
				return
			}
			if event.Op&fsnotify.Create == fsnotify.Create {
				fileName := path.Base(cw.configPath)
				if strings.Contains(event.Name, fileName) {
					cw.done <- true
					cw.errors <- nil
					return
				}
			}
		case <-cw.fsWatcher.Errors:
			cw.done <- false
			cw.errors <- fmt.Errorf("watcher error")
			return
		case <-cw.quit:
			cw.errors <- fmt.Errorf("quit signal received")
			return
		}
	}
}

func (cw *calicoWatcher) getChannels() (chan bool, chan bool, chan error) {
	return cw.done, cw.quit, cw.errors
}

func (cw *calicoWatcher) getTimeout() time.Duration {
	return cw.timeout
}

func (cw *calicoWatcher) addWatchedResources() error {
	return cw.fsWatcher.Add(path.Dir(cw.configPath))
}

func (cw *calicoWatcher) close() error {
	return cw.fsWatcher.Close()
}
