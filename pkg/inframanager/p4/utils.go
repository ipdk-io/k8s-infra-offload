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
	"errors"
	"math/big"
	"net"
	"os"
	"reflect"
	"strings"

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
	MAXMODVAL              = (4095 - 1)
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

// Checks needed for empty or small strings
// For MAC the net library checks for len(s) < 14 so no need
func CheckIPAddress(ip string) error {
	if strings.TrimSpace(ip) == "" || len(ip) == 0 {
		log.Errorf("Empty IP address srting")
		return errors.New("Empty IP Address")
	}

	if net.ParseIP(ip) == nil {
		log.Errorf("IP Address: %s - Invalid", ip)
		return errors.New("Invalid IP Address")
	}
	return nil
}

func ParseIPCIDR(cidr string) (net.IP, *net.IPNet, error) {
	if strings.TrimSpace(cidr) == "" || len(cidr) == 0 {
		log.Errorf("IP CIDR is empty: %s - Invalid", cidr)
		return nil, nil, errors.New("empty CIDR")
	}

	ipv4Addr, ipv4Net, err := net.ParseCIDR(cidr)
	if err != nil {
		log.Errorf("invalid CIDR format: %v", err)
		return nil, nil, err
	}
	return ipv4Addr, ipv4Net, err
}

// Binary conversion functions for int and strings
func ToBytes(data interface{}) []byte {
	buf := new(bytes.Buffer)

	switch v := data.(type) {
	case uint8, uint16, uint32, uint64:
		err := binary.Write(buf, binary.BigEndian, v)
		if err != nil {
			log.Errorf("Failed to converttobytestream")
			return []byte{0x00}
		}
	case int8, int16, int32, int64:
		err := binary.Write(buf, binary.BigEndian, v)
		if err != nil {
			log.Errorf("Failed to converttobytestream")
			return []byte{0x00}
		}
	case string:
		return []byte(v)

	default:
		log.Errorf("unsupported data type: %v", v)
		return []byte{0x00}
	}
	return buf.Bytes()
}

// Binary conversion function for flags
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

// Binary conversion function for IPaddress strings
func Pack32BinaryIP4(ip4Address string) []byte {
	if len(ip4Address) == 0 {
		log.Errorf("IP address string received is Empty")
		ip4Address = "0.0.0.0"
	}
	ipv4Decimal := IP4toInt(net.ParseIP(ip4Address))
	return ToBytes(uint32(ipv4Decimal))
}

var (
	JsonFilePath = "/share/infra/jsonfiles/"
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
	file := JsonFilePath + fileName
	log.Debugf("Json file - %s ", file)

	data, err := os.ReadFile(file)
	if err != nil {
		log.Errorf("File read failed: %v", err)
		return nil
	}
	tableData := make(map[string][]Table)
	err = json.Unmarshal(data, &tableData)
	if err != nil {
		log.Infof("Error unmarshaling JSON: %v", err)
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

// This function updates missing information in the Table struct.
// Updating Table struct members.
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

// This function utilizes the data from the Table struct
// To prepare UpdateTable struct and then adds each instances to map.
// TODO - Add all KeyMatch interfaces
func PrepareTable(tblaction map[string][]UpdateTable, tbl *Table) {
	tblmap := newUpdateTable()

	entrycount := reflect.ValueOf(tbl.EntryCount)
	for i := 0; i < int(entrycount.Int()); i++ {
		keydata := make(map[string]client.MatchInterface)
		keycount := reflect.ValueOf(tbl.KeyCount)
		//For keys - mfs
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
				log.Infof("Invalid datatype received")
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

		//For Action param
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
					log.Infof("Unknown datatype recieved")
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

// This function calls Insert_table_entry or delete_table_entry based on actiontype flag
func ConfigureTable(ctx context.Context, p4RtC *client.Client, P4w P4RtCWrapper, tablenames []string, tblactionmap map[string][]UpdateTable, actionnames []string, actiontype bool) error {

	for i := range tablenames {
		v := tblactionmap[tablenames[i]]
		for k := 0; k < len(v); k++ {
			for j := 0; j < len(v[k].mfs); j++ {
				if actiontype {
					//log.Debugf("Key value %s action value %s", v[k].mfs[j].key, v[k].paramData[j].data)
					//log.Debugf("tablename %s actionname %s", tablenames[i], actionnames[i])
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
					//log.Debugf("Entry added for = %s", tablenames[i])
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
					//log.Debugf("Entry Deleted for = %s", tablenames[i])
				}
			}
		}
	}
	return nil
}

func resetSlices(key *[]interface{}, action *[]interface{}) {
	if key != nil {
		*key = nil
	}
	if action != nil {
		*action = nil
	}
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

const (
	DEFAULT_CNIID_CNT_CACHE = 4094
	DEFAULT_SVCID_CNT_CACHE = 64
)

type IdGenerator struct {
	cniId   uint32
	svcId   uint32
	cniChan chan uint32
	svcChan chan uint32
}

func NewIdGenerator(cni uint32, svc uint32) *IdGenerator {
	//once.Do(func() {
	gen := &IdGenerator{
		cniId:   cni,
		svcId:   svc,
		svcChan: make(chan uint32, DEFAULT_SVCID_CNT_CACHE),
		cniChan: make(chan uint32, DEFAULT_CNIID_CNT_CACHE),
	}
	startCniGen(gen)
	startSvcGen(gen)
	//})
	return gen
}

func startSvcGen(g *IdGenerator) {
	go func() {
		for {
			if g.svcId == DEFAULT_SVCID_CNT_CACHE-1 {
				g.svcId = 1
			} else {
				g.svcId += 1
			}
			g.svcChan <- g.svcId
		}
	}()
}

func startCniGen(g *IdGenerator) {
	go func() {
		for {

			if g.cniId == DEFAULT_CNIID_CNT_CACHE-1 {
				g.cniId = 1
			} else {
				g.cniId += 1
			}
			g.cniChan <- g.cniId
		}
	}()
}

func getSvcId(g *IdGenerator) uint32 {
	return <-g.svcChan
}

func getCniId(g *IdGenerator) uint32 {
	return <-g.cniChan
}

var Mask = []uint8{1, 2, 4, 8, 16, 32, 64, 128}

// this function to generate rulemask or ipsetmask for each rule under each
// ipsetidx
func GenerateMask(index int) uint8 {
	return Mask[index]
}
