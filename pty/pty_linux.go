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
package pty

import (
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"unsafe"
)

func posix_openpt(flags int) (*os.File, error) {
	return os.OpenFile("/dev/ptmx", flags, 0)
}

func ptsname(pty *os.File) (string, error) {
	var n int32
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, pty.Fd(), unix.TIOCGPTN, uintptr(unsafe.Pointer(&n)))
	if errno != 0 {
		pty.Close()
		return "", errno
	}
	return "/dev/pts/" + strconv.Itoa(int(n)), nil
}

func unlockpt(pty *os.File) error {
	var n int32
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, pty.Fd(), unix.TIOCSPTLCK, uintptr(unsafe.Pointer(&n)))
	if errno != 0 {
		pty.Close()
		return errno
	}
	return nil
}

func open_pty() (pty, tty *os.File, err error) {
	pty, err = posix_openpt(os.O_RDWR | unix.O_NOCTTY)
	if err != nil {
		return nil, nil, err
	}

	tty_name, err := ptsname(pty)
	if err != nil {
		pty.Close()
		return nil, nil, err
	}

	err = unlockpt(pty)
	if err != nil {
		pty.Close()
		return nil, nil, err
	}

	tty, err = os.OpenFile(tty_name, os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		pty.Close()
		return nil, nil, err
	}

	return pty, tty, nil
}

func resize_pty(tty *os.File, size *ptyWindow) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, tty.Fd(), unix.TIOCGWINSZ, uintptr(unsafe.Pointer(size)))
	if errno != 0 {
		return errno
	}
	return nil
}

func attach_pty(tty *os.File, cmd *exec.Cmd) error {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setsid = true
	cmd.SysProcAttr.Setctty = true
	cmd.SysProcAttr.Ctty = int(tty.Fd())
	return nil
}
