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
	"bufio"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	SCPCopy = iota
	SCPDir
	SCPEndDir
	SCPTime
)

type SCPCommand struct {
	CommandType int
	Mode        int16
	Length      int64
	Name        string
}

var (
	SCP_END_COMMANDS = "\x00"
	ErrInvalidAck    = errors.New("Invalid ack code.")
	ErrInvalidPieces = errors.New("Invalid number of command pieces.")
)

func parseSCPCommand(cmd string) (*SCPCommand, error) {
	parsePieces := func(cstr string, c *SCPCommand) error {
		pieces := strings.Split(cmd, " ")
		if len(pieces) != 3 {
			return ErrInvalidPieces
		}

		// Mode
		if m, err := strconv.ParseInt(pieces[0][1:], 8, 16); err != nil {
			return err
		} else {
			c.Mode = int16(m)
		}

		// Length
		if m, err := strconv.ParseInt(pieces[1], 10, 64); err != nil {
			return err
		} else {
			c.Length = m
		}

		c.Name = pieces[2]
		return nil
	}

	info := &SCPCommand{}

	switch cmd[0] {
	case 'C':
		info.CommandType = SCPCopy
		if err := parsePieces(cmd, info); err != nil {
			return nil, err
		}
	case 'D':
		info.CommandType = SCPDir
		if err := parsePieces(cmd, info); err != nil {
			return nil, err
		}
	case 'E':
		info.CommandType = SCPEndDir
	case 'T':
		info.CommandType = SCPTime
	default:
		return nil, fmt.Errorf("Unknown message type: %v", cmd[0])
	}
	return info, nil
}

// Manage SCP operations in a built-in fashion
func (conn *ServerConn) SCPHandler(shellCmd []string, ch ssh.Channel) error {
	shellCmd = shellCmd[1:] // pop scp off
	var path string
	var source bool
	var dirMode bool

	for _, opt := range shellCmd {
		switch opt {
		case "-t":
			source = false
		case "-f":
			source = true
		case "-d":
			dirMode = true
		case "-p":
		case "-v":
		default:
			dbg.Debug("scp path: %s", opt)
			path = opt
		}
	}

	if source {
		return conn.SCPSource(path, dirMode, ch)
	}
	return conn.SCPSink(path, dirMode, ch)
}

func (conn *ServerConn) SCPSink(path string, dirMode bool, ch ssh.Channel) error {
	readbuf := bufio.NewReader(ch)
	for {
		if err := scpSendAck(ch, 0, ""); err != nil {
			return err
		}
		// Get the text of the command
		cmd, err := scpReadCommand(readbuf)
		if err != nil {
			if err == io.EOF {
				// EOF here isn't bad
				dbg.Debug("eof in scp sink")
				scpSendAck(ch, 0, "")
				return nil
			}
			scpSendAck(ch, 2, err.Error())
			dbg.Debug("error in scp sink: %v", err)
			return err
		}
		if cmd == SCP_END_COMMANDS {
			dbg.Debug("continue scp")
			continue
		}
		// Parse it
		parsed, err := parseSCPCommand(cmd)
		if err != nil {
			scpSendAck(ch, 2, err.Error())
			dbg.Debug("error in scp sink: %v", err)
			return err
		}
		dbg.Debug("scp command: %v", parsed)
		switch parsed.CommandType {
		case SCPCopy:
			if err := scpSendAck(ch, 0, ""); err != nil {
				return err
			}
			fpath := filepath.Join(path, parsed.Name)
			if err := receiveFile(fpath, parsed, readbuf); err != nil {
				scpSendAck(ch, 2, err.Error())
				return err
			}
		case SCPDir:
			path = filepath.Join(path, parsed.Name)
			if err := maybeMakeDir(path, parsed.Mode); err != nil {
				scpSendAck(ch, 2, err.Error())
				return err
			}
		case SCPEndDir:
			path = filepath.Clean(filepath.Join(path, ".."))
		case SCPTime:
		}
	}
	return nil
}

func receiveFile(name string, cmd *SCPCommand, src io.Reader) error {
	left := cmd.Length
	os.Remove(name) // to rewrite
	fp, err := os.Create(name)
	if err != nil {
		return err
	}
	defer fp.Close()
	if err := fp.Chmod(os.FileMode(cmd.Mode)); err != nil {
		return err
	}
	for left > 0 {
		var max int64 = 2048
		if left < max {
			max = left
		}
		buf := make([]byte, max)
		if n, err := src.Read(buf); err != nil {
			return err
		} else {
			if _, err := fp.Write(buf[:n]); err != nil {
				return err
			}
			left -= int64(n)
		}
	}
	b := make([]byte, 1)
	if _, err := src.Read(b); err != nil {
		return err
	}
	if b[0] != byte(0) {
		return fmt.Errorf("Expected null byte for EOF.")
	}
	return nil
}

func maybeMakeDir(path string, mode int16) error {
	if fi, err := os.Stat(path); err != nil {
		if err := os.Mkdir(path, os.FileMode(mode)); err != nil {
			return err
		}
		return nil
	} else {
		if !fi.IsDir() {
			return fmt.Errorf("Path %s exists, but is not a directory.", path)
		}
		return nil
	}
}

func (conn *ServerConn) SCPSource(path string, dirMode bool, ch ssh.Channel) error {
	return nil
}

func scpReadCommand(src *bufio.Reader) (string, error) {
	buf, err := src.ReadBytes(byte('\n'))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(buf)), nil
}

// Acknowledge SCP message
func scpSendAck(dst io.Writer, code int, msg string) error {
	buf := []byte{byte(code)}
	if code > 2 {
		return ErrInvalidAck
	}
	if code > 0 {
		buf = append(buf, []byte(msg)...)
		buf = append(buf, byte('\n'))
	}
	sent := 0
	for sent < len(buf) {
		s, err := dst.Write(buf[sent:])
		if err != nil {
			return err
		}
		sent += s
	}
	return nil
}
