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
	"bufio"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ipdk-io/k8s-infra-offload/pkg/types"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

type CDQManager interface {
	CreateIntf() (*types.InterfaceInfo, error)
	RemoveIntf(*types.InterfaceInfo) error
}

type cdqManager struct {
	log           *log.Entry
	master        string
	masterPciAddr string
	lastSFnum     int
	portsMap      map[int]string // subfunction port map using sfnum as key to a subfunction port ID
	sync.Mutex
}

var (
	instance                CDQManager
	once                    sync.Once
	portIDRegex             = `(pci\/\d{4}:[\d|a-f]{2}:[\d|a-f]{2}.[0-7]{1}\/\d+)` // portID Regex pattern
	matchMasterPCIAddrRegex = `(pci\/%s\/)`                                        // Master PCI Addr regex pattern
	sfNumRegex              = `sfnum\s(\d+)`                                       // sfnum regex pattern
	netDevRegex             = `netdev ([a-z0-9]+)`                                 // netdev regex pattern
	defaultSFNumber         = 1                                                    // sfnum to use if there's no existing subfunction found
)

// NewCDQManager returns a singleton instance of CDQManager for a master inteface
func NewCDQManager(masterIntf string, log *log.Entry) (CDQManager, error) {
	var err error
	once.Do(func() {
		cdqMgr := &cdqManager{
			master:   masterIntf,
			portsMap: make(map[int]string),
		}
		cdqMgr.log = log
		if err = cdqMgr.setMasterPciAddr(); err != nil {
			return
		}
		if err = cdqMgr.initPortMap(); err != nil {
			return
		}
		instance = cdqMgr
	})

	if err != nil {
		return nil, err
	}
	return instance, nil
}

// setMasterPciAddr finds out the PCI addr from master interface name and use that internally to call
// external CDQ Function during Create/Delete CDQ interface
func (c *cdqManager) setMasterPciAddr() error {
	pciAddr, err := GetIntfPciAddress(c.master, SysClassNet)
	if err != nil {
		return err
	}
	c.masterPciAddr = pciAddr
	log.Debugf("using master interface(%s) PCI address: %s", c.master, c.masterPciAddr)
	return nil
}

// initPortMap finds out existing subfunction for the PF this CDQ manager manages
// It also sets the lastSFnumber for the CDQManager.
func (c *cdqManager) initPortMap() error {
	log.Debugf("initializing CDQManager PortMap")
	c.Lock()
	defer c.Unlock()
	args := []string{"port", "show"}
	stdout, err := execDevlinkFunc(args)
	if err != nil {
		log.Debugf("execDevlinkFunc returned error: %s", err.Error())
		return err
	}
	log.Debugf("'devlink %s' command output: %s", args, stdout)

	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		var sfNum int
		line := scanner.Text()
		// Try to read sfNumber regardless which master ports it belongs to
		sfNum = c.extractSfNum(line)
		if sfNum > 0 {
			// We store the last-known sfnum as 'lastSFNum'. The assumption here from the observation is that devlink port show lists
			// ports in ascending orders. So the last sfnum would be he highest
			c.lastSFnum = sfNum
			masterRegex := regexp.MustCompile(fmt.Sprintf(matchMasterPCIAddrRegex, c.masterPciAddr))
			// Only process lines that matches portID from master PCI address
			if masterRegex.MatchString(line) {
				portID := c.extractPortID(line)
				if portID != "" {
					c.portsMap[sfNum] = portID
					log.Debugf("CDQManager portMap entry added: [%d]: '%s'", sfNum, portID)
				}
			}
		}
	}
	log.Debugf("lastSFnum: %d", c.lastSFnum)

	return nil
}

func (c *cdqManager) extractPortID(line string) string {
	re := regexp.MustCompile(portIDRegex)
	portID := re.FindString(line)
	return portID
}

// extractSfNum will try to find the sfnum from string line and return that as int.
// If no match found it returns 0 which should be treated as invalid sfnum.
func (c *cdqManager) extractSfNum(line string) int {
	sfNum := 0
	re := regexp.MustCompile(sfNumRegex)
	matches := re.FindStringSubmatch(line)
	if matches != nil && len(matches) > 1 {
		sfNumStr := matches[1]
		if num, err := strconv.Atoi(sfNumStr); err == nil {
			sfNum = num
		}
	}
	return sfNum
}

// extractNetDevName will try to find the interface name of subfunciton.
// If no match found it returns empty("") string.
func (c *cdqManager) extractNetDevName(line string) string {
	re := regexp.MustCompile(netDevRegex)
	matches := re.FindStringSubmatch(line)
	if matches != nil && len(matches) > 1 {
		return matches[1]
	}
	return ""
}

var execDevlinkFunc = execDevlink
var commandName = "devlink"

// execDevlink runs devlink command, and returns it's stdout as string
func execDevlink(args []string) (string, error) {
	cmd := exec.Command(commandName, args...)
	stdout, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(stdout), nil
}

// CreateIntf create a CDQ  interface and returns types.InterfaceInfo object containig that interface information
func (c *cdqManager) CreateIntf() (*types.InterfaceInfo, error) {
	log.Debugf("creating new CDQ inteface")
	c.Lock()
	defer c.Unlock()

	newSfNum := c.lastSFnum + 1
	args := []string{"port", "add", fmt.Sprintf("pci/%s", c.masterPciAddr), "flavour", "pcisf", "pfnum", "0", "sfnum", fmt.Sprintf("%d", newSfNum)}
	stdout, err := execDevlinkFunc(args)
	if err != nil {
		log.Debugf("execDevlinkFunc returned error: %s", err.Error())
		return nil, err
	}
	log.Debugf("'devlink %s' command output: %s", args, stdout)
	portID := c.extractPortID(stdout)
	if portID != "" {
		activateOut := c.activatePort(portID)
		intfName := c.extractNetDevName(activateOut)
		if intfName != "" {
			macAddr, err := c.getNetDevMacAddr(intfName)
			if err != nil || macAddr == "" {
				log.Errorf("unable to get mac address for interface for interface name: %s", intfName)
			}
			intfInfo := &types.InterfaceInfo{
				PciAddr:       portID, // Re-using PciAddr
				VfID:          newSfNum,
				InterfaceName: intfName,
				MacAddr:       macAddr,
			}
			c.lastSFnum = newSfNum
			c.portsMap[newSfNum] = portID
			return intfInfo, nil
		}
	}

	return nil, fmt.Errorf("unable to create a new subfunction")
}

// getNetDevMacAddr returns a netdevice mac address as string from it's interface name
// Caller must check the mac address for empty string even if the error is nil.
func (c *cdqManager) getNetDevMacAddr(intfName string) (string, error) {
	link, err := netlink.LinkByName(intfName)
	if err != nil {
		c.log.Errorf("error getting netlink interface for interface name %s", intfName)
		return "", err
	}
	return link.Attrs().HardwareAddr.String(), nil
}

// activatePort activate an subfunciton and then return it's port information as string from stdout
func (c *cdqManager) activatePort(portID string) string {
	args := []string{"port", "function", "set", portID, "state", "active"}
	stdout, err := execDevlinkFunc(args)
	if err != nil {
		log.Debugf("execDevlinkFunc returned error excuting activatePort command: %s", err.Error())
		return ""
	}
	// The delay below is needed for newly created interface to be ready to be configured
	time.Sleep(1 * time.Second)

	args = []string{"port", "show", portID}
	stdout, err = execDevlinkFunc(args)
	if err != nil {
		log.Debugf("execDevlinkFunc returned error while getting port info command: %s", err.Error())
		return ""
	}

	log.Debugf("'devlink %s' command output: %s", args, stdout)
	return stdout
}

// RemoveIntf removes a CDQ interface from infromaiton provide with intfInfo *types.InterfaceInfo
func (c *cdqManager) RemoveIntf(intfInfo *types.InterfaceInfo) error {
	log.Infof("removing a CDQ inteface using InterfaceInfo %v", intfInfo)
	c.Lock()
	defer c.Unlock()

	// deactivate
	args := []string{"port", "function", "set", intfInfo.PciAddr, "state", "inactive"}

	_, err := execDevlinkFunc(args)
	if err != nil {
		log.Errorf("error setting sub-function inactive %s: %v", intfInfo.PciAddr, err.Error())
		return err
	}

	// delete
	args = []string{"port", "del", intfInfo.PciAddr}
	_, err = execDevlinkFunc(args)
	if err != nil {
		log.Errorf("error deleting sub-function %s: %v", intfInfo.PciAddr, err.Error())
		return err
	}

	delete(c.portsMap, intfInfo.VfID)
	return nil
}
