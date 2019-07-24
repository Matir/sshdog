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
	"io/ioutil"
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

const (
	SCPOK = iota
	SCPError
	SCPFatal
)

type SCPCommand struct {
	CommandType int
	Mode        int16
	Length      int64
	Name        string
}

var (
	SCP_END_COMMANDS  = "\x00"
	ErrInvalidAck     = errors.New("Invalid ack code.")
	ErrInvalidPieces  = errors.New("Invalid number of command pieces.")
	ErrNotRegularFile = errors.New("Not a regular file.")
	ErrNotDirectory   = errors.New("Not a directory.")
)

// Manage SCP operations in a built-in fashion
func (conn *ServerConn) SCPHandler(shellCmd []string, ch ssh.Channel) error {
	shellCmd = shellCmd[1:] // pop scp off
	var path string
	var source bool
	var dirMode bool
	var recursive bool

	for _, opt := range shellCmd {
		switch opt {
		case "-t":
			source = false
		case "-f":
			source = true
		case "-d":
			dirMode = true
		case "-r":
			recursive = true
		case "-p":
		case "-v":
		default:
			dbg.Debug("scp path: %s", opt)
			path = opt
		}
	}

	var err error
	if source {
		err = conn.SCPSource(path, dirMode, recursive, ch)
	} else {
		err = conn.SCPSink(path, dirMode, ch)
	}
	if err != nil {
		scpSendError(ch, err)
	}
	ch.CloseWrite()
	return err
}

// Handle the 'source' side of an SCP connection
func (conn *ServerConn) SCPSource(path string, dirMode bool, recursive bool, ch ssh.Channel) error {
	src := bufio.NewReader(ch)
	if err := readAck(src); err != nil {
		return err
	}
	if recursive {
		return SCPSendDir(path, nil, src, ch)
	}
	return SCPSendFile(path, src, ch)
}

// Send a directory
func SCPSendDir(path string, fi os.FileInfo, src *bufio.Reader, dst io.Writer) error {
	if fi == nil {
		if statfi, err := os.Stat(path); err != nil {
			return err
		} else {
			fi = statfi
		}
	}

	dbg.Debug("Preparing to send dir: %s", path)
	cmd := buildSCPCommand(fi)
	if _, err := dst.Write([]byte(cmd)); err != nil {
		return err
	}
	dbg.Debug("sent header")
	if err := readAck(src); err != nil {
		return err
	}

	// Children
	if contents, err := ioutil.ReadDir(path); err != nil {
		scpSendAck(dst, SCPFatal, err.Error())
		return err
	} else {
		for _, child := range contents {
			lpath := filepath.Join(path, child.Name())
			if child.IsDir() {
				SCPSendDir(lpath, child, src, dst)
			} else {
				SCPSendFile2(lpath, child, src, dst)
			}
		}
	}

	if _, err := dst.Write([]byte("E\n")); err != nil {
		return err
	}
	if err := readAck(src); err != nil {
		return err
	}
	dbg.Debug("Done sending dir: %s", path)
	return nil
}

// Send a file
func SCPSendFile(path string, src *bufio.Reader, dst io.Writer) error {
	dbg.Debug("Preparing to send %s", path)
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	return SCPSendFile2(path, fi, src, dst)
}

// Actually send the file
func SCPSendFile2(path string, fi os.FileInfo, src *bufio.Reader, dst io.Writer) error {
	if fi.Mode()&os.ModeType != 0 {
		scpSendAck(dst, SCPFatal, ErrNotRegularFile.Error())
		return ErrNotRegularFile
	}
	fp, err := os.Open(path)
	if err != nil {
		scpSendAck(dst, SCPFatal, err.Error())
		return err
	}
	defer fp.Close()
	cmd := buildSCPCommand(fi)
	if _, err := dst.Write([]byte(cmd)); err != nil {
		return err
	}
	dbg.Debug("sent header")
	if err := readAck(src); err != nil {
		return err
	}
	dbg.Debug("sending data...")
	if _, err := io.Copy(dst, fp); err != nil {
		scpSendAck(dst, SCPFatal, err.Error())
		return err
	}
	dbg.Debug("data sent")
	scpSendAck(dst, SCPOK, "")
	if err := readAck(src); err != nil {
		return err
	}
	dbg.Debug("successfully sent file")
	return nil
}

func buildSCPCommand(fi os.FileInfo) string {
	c := 'C'
	if fi.IsDir() {
		c = 'D'
	}
	ret := fmt.Sprintf("%c%04o %d %s\n",
		c, fi.Mode()&os.ModePerm, fi.Size(), fi.Name())
	dbg.Debug("cmd: %s", strings.TrimSpace(ret))
	return ret
}

// Read an acknowledgement
func readAck(src *bufio.Reader) error {
	if ack, ackMsg, err := readAckDetails(src); err != nil {
		return err
	} else if ack != SCPOK {
		dbg.Debug("SCP Ack error %d, msg \"%s\"", ack, ackMsg)
		return fmt.Errorf("SCP Error %d", ack)
	}
	return nil
}

func readAckDetails(src *bufio.Reader) (int, string, error) {
	b, err := src.ReadByte()
	if err != nil {
		return SCPFatal, "", err
	}
	if b > SCPFatal {
		return SCPFatal, "", fmt.Errorf("%d is not a valid SCP status code", b)
	}
	if b > SCPOK {
		msg, err := src.ReadString('\n')
		if err != nil {
			return SCPFatal, "", err
		}
		return int(b), strings.TrimRight(msg, "\n"), nil
	}
	return SCPOK, "", nil
}

// Handle the 'sink' side of an SCP connection
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

// receive the single file from the scp stream
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
	// TODO: refactor to io.CopyN
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

// Make a directory if it doesn't exist
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

// Read a command from the SCP channel
func scpReadCommand(src *bufio.Reader) (string, error) {
	buf, err := src.ReadBytes(byte('\n'))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(buf)), nil
}

// Parse the SCP command
func parseSCPCommand(cmd string) (*SCPCommand, error) {
	parsePieces := func(cstr string, c *SCPCommand) error {
		pieces := strings.SplitN(cmd, " ", 3)
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

// Acknowledge SCP message
func scpSendAck(dst io.Writer, code int, msg string) error {
	buf := []byte{byte(code)}
	if code > SCPFatal {
		return ErrInvalidAck
	}
	if code > SCPOK {
		buf = append(buf, []byte(msg)...)
		buf = append(buf, byte('\n'))
	}
	return scpWriter(dst, buf)
}

// Send an error message
func scpSendError(dst io.Writer, err error) error {
	buf := []byte("\x01scp: ")
	buf = append(buf, []byte(err.Error())...)
	buf = append(buf, byte('\n'))
	return scpWriter(dst, buf)
}

// Write all bytes
func scpWriter(dst io.Writer, buf []byte) error {
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
