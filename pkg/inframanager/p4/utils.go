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
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"
	"reflect"

	"github.com/antoninbas/p4runtime-go-client/pkg/client"
	log "github.com/sirupsen/logrus"
)

type InterfaceType int

const (
	HOST InterfaceType = iota
	PROXY
	ENDPOINT
	EXCEPTION
)

const (
	Insert InterfaceType = iota
	Delete
	Update
)

const (
	MAXUINT32              = 4294967295
	DEFAULT_UUID_CNT_CACHE = 512
	PROTO_TCP              = 6
	PROTO_UDP              = 17
)

type UUIDGenerator struct {
	idGen        uint32
	internalChan chan uint32
}

type ActionParam struct {
	data [][]byte
}

type KeyData struct {
	key map[string]client.MatchInterface
}

// its a common structure to insert and delete entries from table
type UpdateTable struct {
	tableName  string
	mfs        []KeyData
	actionName string
	paramData  []ActionParam
}

var tblupdate *UpdateTable

var Env string
var P4w P4RtCWrapper

var (
	P4FilePath = "/share/infra/p4files/"
)

// Structure reads table details from json file
type Table struct {
	TableName        string        `json:"tableName"`
	ActionName       string        `json:"actionName"`
	EntryCount       int           `json:"entryCount"`
	KeyCount         int           `json:"keyCount"`
	ActionParamCount int           `json:"actionParamCount"`
	KeyMatchType     []string      `json:"keyMatchType"`
	KeyName          []string      `json:"keyName"`
	Key              []interface{} `json:"-"`
	Action           []interface{} `json:"-"`
}

func parseJson(fileName string) map[string][]Table {
	file := P4FilePath + fileName
	fmt.Println(file)

	data, err := os.ReadFile(file)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return nil
	}

	tableData := make(map[string][]Table)

	err = json.Unmarshal(data, &tableData)
	if err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		return nil
	}

	return tableData
}

func newTable() *Table {
	tbl := &Table{KeyMatchType: make([]string, 0),
		KeyName: make([]string, 0),
		Key:     make([]interface{}, 0),
		Action:  make([]interface{}, 0),
	}

	return tbl
}

func newUpdateTable() UpdateTable {
	tblupdate := UpdateTable{mfs: make([]KeyData, 0),
		paramData: make([]ActionParam, 0)}

	return tblupdate
}

// Updating table structure members
func updateTables(tableName string, tableData map[string][]Table, svcmap map[string][]UpdateTable, keyparams []interface{}, actionparams []interface{}, entrycount int) {
	entries, exists := tableData[tableName]
	if exists {

		for _, entry := range entries {
			entry.EntryCount = entrycount
			entry.Key = keyparams
			entry.Action = actionparams

			PrepareTable(svcmap, &entry)
		}
	} else {
		log.Errorf("Table %s is missing in json", tableName)
	}
}

func PrepareTable(tblaction map[string][]UpdateTable, tbl *Table) {
	tblmap := newUpdateTable()

	entrycount := reflect.ValueOf(tbl.EntryCount)
	for i := 0; i < int(entrycount.Int()); i++ {
		keydata := make(map[string]client.MatchInterface)
		keycount := reflect.ValueOf(tbl.KeyCount)
		for j := 0; j < int(keycount.Int()); j++ {
			var value []byte
			a := tbl.Key[j]
			in := reflect.ValueOf(tbl.Key[j])
			switch a.(type) {
			case [][]byte:
				value = in.Index(i).Bytes()
			case []byte:
				value = in.Bytes()
			default:
				fmt.Println("inside default")
			}
			if tbl.KeyMatchType[j] == "Exact" {
				keydata[tbl.KeyName[j]] = &client.ExactMatch{
					Value: value}
			} //TODO: add conditions for LPM, Ternary as well, will be handled during policy implementation
		}
		kd := KeyData{
			key: keydata,
		}
		tblmap.mfs = append(tblmap.mfs, kd)

		if tbl.Action != nil {
			action := make([][]byte, 0)
			actionparamcount := reflect.ValueOf(tbl.ActionParamCount)
			for k := 0; k < int(actionparamcount.Int()); k++ {
				var value []byte
				a := tbl.Action[k]
				in := reflect.ValueOf(tbl.Action[k])
				switch a.(type) {
				case [][]byte:
					value = in.Index(i).Bytes()
				case []byte:
					value = in.Bytes()
				default:
					fmt.Println("inside default")
				}
				action = append(action, value)
			}
			ad := ActionParam{
				data: action,
			}
			tblmap.paramData = append(tblmap.paramData, ad)
		} else {
			//Required for insert case with zero action parameters
			ad := ActionParam{}
			tblmap.paramData = append(tblmap.paramData, ad)
		}
	}
	tblmap.tableName = tbl.TableName
	tblmap.actionName = tbl.ActionName

	tblaction[tblmap.tableName] = append(tblaction[tblmap.tableName], tblmap)
}

func ConfigureTable(ctx context.Context, p4RtC *client.Client, P4w P4RtCWrapper, tablenames []string, tblactionmap map[string][]UpdateTable, actionnames []string, flag bool) error {

	for i := range tablenames {
		v := tblactionmap[tablenames[i]]
		for k := 0; k < len(v); k++ {
			for j := 0; j < len(v[k].mfs); j++ {
				if flag {
					log.Debugf("Key value %s action value %s", v[k].mfs[j].key, v[k].paramData[j].data)
					log.Debugf("tablename %s actionname %s", tablenames[i], actionnames[i])
					entryAdd := P4w.NewTableEntry(
						p4RtC,
						tablenames[i],
						v[k].mfs[j].key,
						P4w.NewTableActionDirect(p4RtC, actionnames[i], v[k].paramData[j].data),
						nil,
					)
					if err := P4w.InsertTableEntry(ctx, p4RtC, entryAdd); err != nil {
						log.Errorf("Failed to add entry in %s table, err: %v", tablenames[i], err)
						return err
					}
					log.Debugf("Entry added for = %s", tablenames[i])
				} else {
					entryDel := P4w.NewTableEntry(
						p4RtC,
						tablenames[i],
						v[k].mfs[j].key,
						nil,
						nil,
					)
					if err := P4w.DeleteTableEntry(ctx, p4RtC, entryDel); err != nil {
						log.Errorf("Failed to delete entry in %s table, err: %v", tablenames[i], err)
						return err
					}
					log.Debugf("Entry Deleted for = %s", tablenames[i])
				}
			}
		}
	}
	return nil
}

func GetStr(action InterfaceType) string {
	switch action {
	case Insert:
		return "insert"
	case Delete:
		return "delete"
	case Update:
		return "update"
	default:
		return ""
	}
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

func ValueToBytes(value uint32) []byte {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, value)
	if err != nil {
		fmt.Println("binary.Write failed:", err)
	}
	fmt.Printf("% x", buf.Bytes())
	return buf.Bytes()
}

func ValueToBytes8(value uint8) []byte {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, value)
	if err != nil {
		fmt.Println("binary.Write failed:", err)
	}
	fmt.Printf("% x", buf.Bytes())
	return buf.Bytes()
}

func ValueToBytes16(value uint16) []byte {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, value)
	if err != nil {
		fmt.Println("binary.Write failed:", err)
	}
	fmt.Printf("% x", buf.Bytes())
	return buf.Bytes()
}

func valueToBytesStr(value string) []byte {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, value)
	if err != nil {
		fmt.Println("binary.Write failed:", err)
	}
	fmt.Printf("% x", buf.Bytes())
	return buf.Bytes()
}

func converttobytestream(value uint8) []byte {
	if value == 0x00 {
		buf0 := []byte{0x00}
		return buf0
	} else {
		buf1 := []byte{0x01}
		return buf1
	}
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

var Mask = []uint8{1, 2, 4, 8, 16, 32, 64, 128}

// this function to generate rulemask or ipsetmask for each rule under each
// ipsetidx
func GenerateMask(index int) uint8 {
	return Mask[index]
}
