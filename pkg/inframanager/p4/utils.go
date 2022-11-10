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

package p4

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
)

type InterfaceType int

const (
	HOST InterfaceType = iota
	PROXY
	ENDPOINT
	EXCEPTION
)

const (
	MAXUINT32              = 4294967295
	DEFAULT_UUID_CNT_CACHE = 512
)

type UUIDGenerator struct {
	idGen        uint32
	internalChan chan uint32
}

func newUUIDGenerator() *UUIDGenerator {
	gen := &UUIDGenerator{
		idGen:        0,
		internalChan: make(chan uint32, DEFAULT_UUID_CNT_CACHE),
	}
	gen.startGen()
	return gen
}

// Open goroutine and put the generated UUID in digital form into the buffer pipe
func (this *UUIDGenerator) startGen() {
	go func() {
		for {
			if this.idGen == MAXUINT32 {
				this.idGen = 1
			} else {
				this.idGen += 1
			}
			this.internalChan <- this.idGen
		}
	}()
}

// Get UUID in uint32 form
func (this *UUIDGenerator) getUUID() uint32 {
	return <-this.internalChan
}

var uuidFactory = newUUIDGenerator()

func valueToBytes(value uint32) []byte {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, value)
	if err != nil {
		fmt.Println("binary.Write failed:", err)
	}
	fmt.Printf("% x", buf.Bytes())
	return buf.Bytes()
}

func valueToBytes16(value uint16) []byte {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, value)
	if err != nil {
		fmt.Println("binary.Write failed:", err)
	}
	fmt.Printf("% x", buf.Bytes())
	return buf.Bytes()
}

func IP4toInt(IPv4Address net.IP) int64 {
	IPv4Int := big.NewInt(0)
	IPv4Int.SetBytes(IPv4Address.To4())
	return IPv4Int.Int64()
}

func Pack32BinaryIP4(ip4Address string) []byte {
	ipv4Decimal := IP4toInt(net.ParseIP(ip4Address))

	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, uint32(ipv4Decimal))

	if err != nil {
		fmt.Println("Unable to write to buffer:", err)
	}

	// present in hexadecimal format
	//fmt.Sprintf("%x", buf.Bytes())
	return buf.Bytes()
}
