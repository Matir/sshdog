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
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Matir/sshdog/daemon"
	"golang.org/x/crypto/ssh"
)

func getConfigDir() string {
	selfPath, err := os.Executable()
	if err != nil {
		return "config"
	}
	return filepath.Join(filepath.Dir(selfPath), "config")
}

type Config struct {
	port            uint16
	quiet           bool
	daemon          bool
	privkey         []byte
	pubkey          []byte
	authorized_keys []byte
}

type EmbeddedConfig struct {
	Port           uint16   `json:"port"`
	Daemon         bool     `json:"daemon"`
	Debug          bool     `json:"debug"`
	HostKeys       [][]byte `json:"host_keys"`
	AuthorizedKeys []byte   `json:"authorized_keys"`
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
	subcommand := "serve"
	var args []string
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "serve":
			subcommand = "serve"
			args = os.Args[2:]
		case "embed":
			subcommand = "embed"
			args = os.Args[2:]
		default:
			if strings.HasPrefix(os.Args[1], "-") {
				subcommand = "serve"
				args = os.Args[1:]
			} else {
				fmt.Fprintf(os.Stderr, "Unknown subcommand: %s\n", os.Args[1])
				os.Exit(1)
			}
		}
	} else {
		args = []string{}
	}

	switch subcommand {
	case "serve":
		runServe(args)
	case "embed":
		runEmbed(args)
	}
}

func loadEmbeddedConfig() (*EmbeddedConfig, error) {
	selfPath, err := os.Executable()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(selfPath)
	if err != nil {
		return nil, err
	}

	magic := []byte{'S', 'S', 'H', 'D', 'O', 'G', '-', 'E', 'M', 'B', 'E', 'D', 'D', 'E', 'D', '-', 'C', 'O', 'N', 'F', 'I', 'G'}
	idx := bytes.LastIndex(data, magic)
	if idx == -1 {
		return nil, fmt.Errorf("no magic string found")
	}
	if idx%4096 != 0 {
		return nil, fmt.Errorf("magic string found but not at 4096 boundary (offset %d)", idx)
	}

	configData := data[idx+len(magic):]
	var cfg EmbeddedConfig
	if err := json.Unmarshal(configData, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal embedded config: %v", err)
	}
	return &cfg, nil
}

func runServe(args []string) {
	embeddedCfg, err := loadEmbeddedConfig()
	if err != nil {
		dbg.Debug("No embedded config found or failed to load: %v", err)
	}

	serveFlags := flag.NewFlagSet("serve", flag.ExitOnError)
	
	defaultPort := 2222
	if embeddedCfg != nil {
		defaultPort = int(embeddedCfg.Port)
	}

	flagPort := serveFlags.Uint("port", uint(defaultPort), "Port to listen on")
	flagAuthorizedKeys := serveFlags.String("authorized_keys", "", "Path to authorized_keys file")
	flagServerKeys := serveFlags.String("server_keys", "", "Comma separated set of paths to host private keys")
	flagForeground := serveFlags.Bool("foreground", false, "Do not daemonize")
	flagDebug := serveFlags.Bool("debug", true, "Enable debug output")

	serveFlags.Parse(args)

	flagsSet := make(map[string]bool)
	serveFlags.Visit(func(f *flag.Flag) {
		flagsSet[f.Name] = true
	})

	debug := true
	if flagsSet["debug"] {
		debug = *flagDebug
	} else if embeddedCfg != nil {
		debug = embeddedCfg.Debug
	}
	dbg = Debugger(debug)

	daemonize := true
	if flagsSet["foreground"] {
		daemonize = !*flagForeground
	} else if embeddedCfg != nil {
		daemonize = embeddedCfg.Daemon
	}
	cfg.daemon = daemonize

	port := uint16(*flagPort)
	if port > 65535 {
		fmt.Fprintf(os.Stderr, "Invalid port: %d\n", port)
		os.Exit(1)
	}
	cfg.port = port

	if cfg.daemon {
		if err := daemon.Daemonize(func() (func(), func()) {
			return daemonStart(embeddedCfg, flagsSet, flagServerKeys, flagAuthorizedKeys)
		}); err != nil {
			dbg.Debug("Error daemonizing: %v", err)
		}
	} else {
		waitFunc, _ := daemonStart(embeddedCfg, flagsSet, flagServerKeys, flagAuthorizedKeys)
		if waitFunc != nil {
			waitFunc()
		}
	}
}

func daemonStart(embeddedCfg *EmbeddedConfig, flagsSet map[string]bool, flagServerKeys *string, flagAuthorizedKeys *string) (waitFunc func(), stopFunc func()) {
	server := NewServer()

	hasHostKeys := false

	if flagsSet["server_keys"] {
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
	} else if embeddedCfg != nil && len(embeddedCfg.HostKeys) > 0 {
		dbg.Debug("Using embedded host keys.")
		for _, keyData := range embeddedCfg.HostKeys {
			if err := server.AddHostkey(keyData); err != nil {
				dbg.Debug("Error adding embedded public key: %v", err)
			} else {
				hasHostKeys = true
			}
		}
	} else {
		for _, keyName := range keyNames {
			keyPath := filepath.Join(getConfigDir(), keyName)
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
	if flagsSet["authorized_keys"] {
		authData, err = os.ReadFile(*flagAuthorizedKeys)
		if err != nil {
			dbg.Debug("Error reading authorized_keys: %v", err)
			return
		}
	} else if embeddedCfg != nil && embeddedCfg.AuthorizedKeys != nil {
		dbg.Debug("Using embedded authorized keys.")
		authData = embeddedCfg.AuthorizedKeys
	} else {
		authPath := filepath.Join(getConfigDir(), "authorized_keys")
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

func runEmbed(args []string) {
	embedFlags := flag.NewFlagSet("embed", flag.ExitOnError)
	flagPort := embedFlags.Uint("port", 2222, "Port to listen on")
	flagAuthorizedKeys := embedFlags.String("authorized_keys", "", "Path to authorized_keys file")
	flagServerKeys := embedFlags.String("server_keys", "", "Comma separated set of paths to host private keys")
	flagForeground := embedFlags.Bool("foreground", false, "Do not daemonize")
	flagDebug := embedFlags.Bool("debug", true, "Enable debug output")
	flagOutput := embedFlags.String("output", "", "Path to output binary")

	embedFlags.Parse(args)

	selfPath, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get executable path: %v\n", err)
		os.Exit(1)
	}
	binData, err := os.ReadFile(selfPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read executable: %v\n", err)
		os.Exit(1)
	}

	magic := []byte{'S', 'S', 'H', 'D', 'O', 'G', '-', 'E', 'M', 'B', 'E', 'D', 'D', 'E', 'D', '-', 'C', 'O', 'N', 'F', 'I', 'G'}
	idx := bytes.LastIndex(binData, magic)
	if idx != -1 && idx%4096 == 0 {
		dbg.Debug("Stripping existing embedded config from source binary.")
		binData = binData[:idx]
	}

	var embeddedCfg EmbeddedConfig
	embeddedCfg.Port = uint16(*flagPort)
	embeddedCfg.Daemon = !*flagForeground
	embeddedCfg.Debug = *flagDebug

	if *flagAuthorizedKeys != "" {
		data, err := os.ReadFile(*flagAuthorizedKeys)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read authorized keys: %v\n", err)
			os.Exit(1)
		}
		if err := validateAuthorizedKeys(data); err != nil {
			fmt.Fprintf(os.Stderr, "Invalid authorized keys: %v\n", err)
			os.Exit(1)
		}
		embeddedCfg.AuthorizedKeys = data
	}
	if *flagServerKeys != "" {
		for _, p := range strings.Split(*flagServerKeys, ",") {
			data, err := os.ReadFile(p)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to read server key %s: %v\n", p, err)
				os.Exit(1)
			}
			if err := validatePrivateKey(data); err != nil {
				fmt.Fprintf(os.Stderr, "Invalid private key %s: %v\n", p, err)
				os.Exit(1)
			}
			embeddedCfg.HostKeys = append(embeddedCfg.HostKeys, data)
		}
	}

	jsonData, err := json.Marshal(embeddedCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal config: %v\n", err)
		os.Exit(1)
	}

	paddedLen := ((len(binData) + 4095) / 4096) * 4096
	outBuf := bytes.NewBuffer(make([]byte, 0, paddedLen+len(magic)+len(jsonData)))
	outBuf.Write(binData)
	paddingLen := paddedLen - len(binData)
	outBuf.Write(make([]byte, paddingLen))

	outBuf.Write(magic)
	outBuf.Write(jsonData)

	outputPath := *flagOutput
	if outputPath == "" {
		outputPath = selfPath + ".embedded"
	}
	err = os.WriteFile(outputPath, outBuf.Bytes(), 0755)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write embedded binary: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Embedded binary written to %s\n", outputPath)
}

func validateAuthorizedKeys(data []byte) error {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	rest := data
	for len(rest) > 0 {
		_, _, _, left, err := ssh.ParseAuthorizedKey(rest)
		if err != nil {
			return err
		}
		rest = left
	}
	return nil
}

func validatePrivateKey(data []byte) error {
	_, err := ssh.ParsePrivateKey(data)
	return err
}

