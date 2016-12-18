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

// "Daemonize" a process on linux

package daemon

import (
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// Attempts to restart this process in the background.
// This is not a *true* daemonize, as the process is
// restarted.
func Daemonize(f DaemonWorker) error {
	if done, err := alreadyDaemonized(); err != nil {
		return err
	} else if done {
		waitFunc, _ := f()
		waitFunc()
		return nil
	}

	bin, err := filepath.EvalSymlinks("/proc/self/exe")
	if err != nil {
		return err
	}

	cmd := exec.Command(bin)
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}

	// No I/O
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil

	// Setup some other stuff
	cmd.Dir = "/"

	// Prevent signals from getting there
	cmd.SysProcAttr.Setsid = true

	err = cmd.Start()
	if err == nil {
		os.Exit(0) // kill the parent
	}
	return err
}

func alreadyDaemonized() (bool, error) {
	if sid, err := unix.Getsid(unix.Getpid()); err != nil {
		return false, err
	} else {
		return sid == unix.Getpid(), nil
	}
}
