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

// Wait for Calico config file created in given location, if file does not exist wait until it will be created
// for given time or forever if timeout == 0, returns errors on fail or nil if file was created
func WaitForCalicoConfig(timeout time.Duration, configPath string) error {
	// check if file exist
	if _, err := os.Stat(configPath); err == nil {
		return nil
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()
	done := make(chan bool)
	quit := make(chan bool)

	go handleEvents(watcher, done, quit, configPath)

	if err := watcher.Add(path.Dir(configPath)); err != nil {
		return err
	}
	// block
	var result bool
	if timeout > 0 {
		// wait until timeout
		select {
		case <-time.After(timeout):
			quit <- true
			return fmt.Errorf("timeout while waiting for Calico config")
		case result = <-done:
			if !result {
				return fmt.Errorf("error while waiting for a Calico config")
			}
			return nil
		}
	} else {
		// wait forever
		result = <-done
		if !result {
			return fmt.Errorf("error while waiting for a Calico config")
		}
	}

	return nil
}

func handleEvents(watcher *fsnotify.Watcher, done chan<- bool, quit <-chan bool, configPath string) {
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				done <- false
				return
			}
			if event.Op&fsnotify.Create == fsnotify.Create {
				fileName := path.Base(configPath)
				if strings.Contains(event.Name, fileName) {
					done <- true
					return
				}
			}
		case <-watcher.Errors:
			done <- false
			return
		case <-quit:
			return
		}
	}
}
