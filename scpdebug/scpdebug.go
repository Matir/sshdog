// Copyright 2017 Google Inc.
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

// Tool for debug logs of SCP, since it's an undocumented protocol.
package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
)

func main() {
	logf, err := os.Create("/tmp/scplog")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		return
	}
	fmt.Fprintf(logf, "CMD: ssh %s\n", strings.Join(os.Args[1:], " "))
	cmd := exec.Command("ssh", os.Args[1:]...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		return
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		return
	}
	lock := &sync.Mutex{}
	// First copy
	go func() {
		buf := make([]byte, 1024, 1024)
	outer:
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", err.Error())
				break
			}
			lock.Lock()
			fmt.Fprintf(logf, "> %s\n", hex.EncodeToString(buf[:n]))
			fmt.Fprintf(logf, "> %s\n", string(buf[:n]))
			lock.Unlock()
			written := 0
			for written < n {
				wr, err := stdin.Write(buf[written:n])
				written += wr
				if err != nil {
					fmt.Fprintf(os.Stderr, "%s\n", err.Error())
					break outer
				}
			}
		}
	}()
	go func() {
		buf := make([]byte, 1024, 1024)
	outer:
		for {
			n, err := stdout.Read(buf)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", err.Error())
				break
			}
			lock.Lock()
			fmt.Fprintf(logf, "< %s\n", hex.EncodeToString(buf[:n]))
			fmt.Fprintf(logf, "< %s\n", string(buf[:n]))
			lock.Unlock()
			written := 0
			for written < n {
				wr, err := os.Stdout.Write(buf[written:n])
				written += wr
				if err != nil {
					fmt.Fprintf(os.Stderr, "%s\n", err.Error())
					break outer
				}
			}
		}
	}()
	cmd.Run()
}
