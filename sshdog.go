// Copyright 2016 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// TODO: High-level file comment.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Matir/sshdog/daemon"
)

const defaultConfigDir = "config"

var (
	flagPort           = flag.Uint("port", 2222, "Port to listen on")
	flagAuthorizedKeys = flag.String("authorized_keys", "", "Path to authorized_keys file")
	flagServerKeys     = flag.String("server_keys", "", "Comma separated set of paths to host private keys")
	flagForeground     = flag.Bool("foreground", false, "Do not daemonize")
)

type Config struct {
	port            uint16
	quiet           bool
	daemon          bool
	privkey         []byte
	pubkey          []byte
	authorized_keys []byte
}

type Debugger bool

func (d Debugger) Debug(format string, args ...interface{}) {
	if d {
		msg := fmt.Sprintf(format, args...)
		fmt.Fprintf(os.Stderr, "[DEBUG] %s\n", msg)
	}
}

var dbg Debugger = true

var cfg = &Config{}

func main() {
	flag.Parse()

	if *flagPort > 65535 {
		fmt.Fprintf(os.Stderr, "Invalid port: %d\n", *flagPort)
		os.Exit(1)
	}

	cfg.port = uint16(*flagPort)
	cfg.daemon = !*flagForeground

	if cfg.quiet {
		dbg = false
	}

	if cfg.daemon {
		if err := daemon.Daemonize(daemonStart); err != nil {
			dbg.Debug("Error daemonizing: %v", err)
		}
	} else {
		waitFunc, _ := daemonStart()
		if waitFunc != nil {
			waitFunc()
		}
	}
}

// Actually run the implementation of the daemon
func daemonStart() (waitFunc func(), stopFunc func()) {
	server := NewServer()

	hasHostKeys := false
	if *flagServerKeys != "" {
		for _, keyPath := range strings.Split(*flagServerKeys, ",") {
			keyData, err := os.ReadFile(keyPath)
			if err != nil {
				dbg.Debug("Error reading host key %s: %v", keyPath, err)
				continue
			}
			dbg.Debug("Adding hostkey file: %s", keyPath)
			if err = server.AddHostkey(keyData); err != nil {
				dbg.Debug("Error adding public key: %v", err)
			}
			hasHostKeys = true
		}
	} else {
		for _, keyName := range keyNames {
			keyPath := filepath.Join(defaultConfigDir, keyName)
			if keyData, err := os.ReadFile(keyPath); err == nil {
				dbg.Debug("Adding hostkey file: %s", keyPath)
				if err = server.AddHostkey(keyData); err != nil {
					dbg.Debug("Error adding public key: %v", err)
				}
				hasHostKeys = true
			}
		}
	}
	if !hasHostKeys {
		if err := server.RandomHostkey(); err != nil {
			dbg.Debug("Error adding random hostkey: %v", err)
			return
		}
	}

	var authData []byte
	var err error
	if *flagAuthorizedKeys != "" {
		authData, err = os.ReadFile(*flagAuthorizedKeys)
		if err != nil {
			dbg.Debug("Error reading authorized_keys: %v", err)
			return
		}
	} else {
		authPath := filepath.Join(defaultConfigDir, "authorized_keys")
		authData, err = os.ReadFile(authPath)
		if err != nil {
			dbg.Debug("No authorized keys found: %v", err)
			return
		}
	}
	dbg.Debug("Adding authorized_keys.")
	server.AddAuthorizedKeys(authData)

	port := cfg.port
	if port == 0 {
		port = 2222
	}
	server.ListenAndServe(port)
	return server.Wait, server.Stop
}
