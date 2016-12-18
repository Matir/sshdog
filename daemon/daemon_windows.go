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

package daemon

import (
	"errors"
	"fmt"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"os"
	"path/filepath"
)

var ErrUnsupported = errors.New("Not yet supported.")

var WindowsServiceName = "sshdog"

func Daemonize(f DaemonWorker) error {
	if interactive, err := svc.IsAnInteractiveSession(); err != nil {
		return err
	} else if interactive {
		return installWindowsService(true)
	}
	return runWindowsService(f)
}

func installWindowsService(start bool) error {
	exePath, err := findExePath()
	if err != nil {
		return err
	}
	svcMgr, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer svcMgr.Disconnect()
	if s, err := svcMgr.OpenService(WindowsServiceName); err == nil {
		// Already installed
		defer s.Close()
		if len(os.Args) > 1 && os.Args[1] == "uninstall" {
			err = s.Delete()
			if err != nil {
				return err
			}
		}
		return nil
	}
	cfg := mgr.Config{
		StartType:    mgr.StartAutomatic,
		Description:  "sshdog rcs",
		ErrorControl: mgr.ErrorIgnore,
	}
	if s, err := svcMgr.CreateService(WindowsServiceName, exePath, cfg); err != nil {
		return err
	} else {
		defer s.Close()
		if start {
			if err := s.Start(); err != nil {
				return err
			}
		}
	}
	return nil
}

func runWindowsService(f DaemonWorker) error {
	// This is probably more involved
	svcHandler := &winService{f}
	return svc.Run(WindowsServiceName, svcHandler)
}

// Find path to the current exe
func findExePath() (string, error) {
	prog := os.Args[0]
	p, err := filepath.Abs(prog)
	if err != nil {
		return "", err
	}
	isFile := func(fi os.FileInfo) bool {
		return fi.Mode()&os.ModeType == 0
	}
	fi, err := os.Stat(p)
	if err == nil {
		if isFile(fi) {
			return p, nil
		}
		err = fmt.Errorf("%s is not a file", p)
	}
	if filepath.Ext(p) == "" {
		p += ".exe"
		fi, err := os.Stat(p)
		if err == nil {
			if isFile(fi) {
				return p, nil
			}
			err = fmt.Errorf("%s is not a file", p)
		}
	}
	return "", err
}

// Service handler
type winService struct{ mainFunc DaemonWorker }

func (s *winService) Execute(args []string, cmdChan <-chan svc.ChangeRequest, statChan chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	waitFunc, stopFunc := s.mainFunc()
	if stopFunc == nil {
		return true, 1
	}
	statChan <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

loop:
	for {
		if cmd, ok := <-cmdChan; !ok {
			break
		} else {
			switch cmd.Cmd {
			case svc.Interrogate:
				statChan <- cmd.CurrentStatus
			case svc.Stop, svc.Shutdown:
				statChan <- svc.Status{State: svc.StopPending}
				stopFunc()
				waitFunc()
				break loop
			}
		}
	}
	return false, 0
}
