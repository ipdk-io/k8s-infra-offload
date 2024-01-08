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
	"io"
	"os"
	"path"
	"time"

	log "github.com/sirupsen/logrus"
)

func GetNodeIPFromEnv() (ipAddr string, err error) {
	ipAddr = os.Getenv("NODE_IP")
	if len(ipAddr) == 0 {
		err = fmt.Errorf("NODE_IP env variable is not set")
	}
	return ipAddr, err
}
func LogInit(logDir string, logLevel string) error {
	logFilename := path.Join(logDir, path.Base(os.Args[0])+".log")
	verifiedFileName, err := VerifiedFilePath(logFilename, logDir)
	if err != nil {
		return err
	}

	err = os.MkdirAll(logDir, 0600)
	if err != nil {
		return err
	}

	logFile, err := os.OpenFile(verifiedFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}

	log.Println("Log level set to ", logLevel)
	log.Println("Created log file ", verifiedFileName)

	mw := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(mw)

	switch logLevel {
	case "Panic":
		log.SetLevel(log.PanicLevel)
	case "Fatal":
		log.SetLevel(log.FatalLevel)
	case "Error":
		log.SetLevel(log.ErrorLevel)
	case "Warn":
		log.SetLevel(log.WarnLevel)
	case "Info":
		log.SetLevel(log.InfoLevel)
	case "Debug":
		log.SetLevel(log.DebugLevel)
	case "Trace":
		log.SetLevel(log.TraceLevel)
	default:
		log.SetLevel(log.DebugLevel)
	}

	log.SetReportCaller(true)
	log.SetFormatter(&log.TextFormatter{
		PadLevelText:     true,
		QuoteEmptyFields: true,
	})
	return nil
}

func unixMilli(t time.Time) uint64 {
	s := t.Round(time.Millisecond).UnixNano() / (int64(time.Millisecond) / int64(time.Nanosecond))
	return uint64(s)
}

func MakeTimestampMilli() uint64 {
	return unixMilli(time.Now())
}
