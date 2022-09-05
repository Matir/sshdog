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
package sshdog

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/matir/sshdog/dbg"
	"golang.org/x/crypto/ssh"
)

// Manage the SSH Server
type Server struct {
	ServerConfig   ssh.ServerConfig
	Socket         net.Listener
	AuthorizedKeys map[string]bool
	stop           chan bool
	done           chan bool
}

var KeyNames = []string{
	"ssh_host_dsa_key",
	"ssh_host_ecdsa_key",
	"ssh_host_rsa_key",
}

func NewServer() *Server {
	s := &Server{}
	s.AuthorizedKeys = make(map[string]bool)
	s.ServerConfig.PublicKeyCallback = s.VerifyPublicKey
	s.stop = make(chan bool)
	s.done = make(chan bool, 1)
	return s
}

func (s *Server) listen(port int16) error {
	sPort := ":" + strconv.Itoa(int(port))
	if sock, err := net.Listen("tcp", sPort); err != nil {
		dbg.Debug("Unable to listen: %v", err)
		return err
	} else {
		dbg.Debug("Listening on %s", sPort)
		s.Socket = sock
	}
	return nil
}

func (s *Server) acceptChannel() <-chan net.Conn {
	c := make(chan net.Conn)
	go func() {
		defer close(c)
		for {
			conn, err := s.Socket.Accept()
			if err != nil {
				dbg.Debug("Unable to accept: %v", err)
				return
			}
			dbg.Debug("Accepted connection from: %s", conn.RemoteAddr())
			c <- conn
		}
	}()
	return c
}

func (s *Server) handleConn(conn net.Conn) {
	sConn, err := NewServerConn(conn, s)
	if err != nil {
		if err == io.EOF {
			dbg.Debug("Connection closed by remote host.")
			return
		}
		dbg.Debug("Unable to negotiate SSH: %v", err)
		return
	}
	dbg.Debug("Authenticated client from: %s", sConn.RemoteAddr())

	go sConn.HandleConn()
}

func (s *Server) serveLoop() error {
	acceptChan := s.acceptChannel()
	defer func() {
		dbg.Debug("done serveLoop")
		s.Socket.Close()
		s.done <- true
	}()
	for {
		dbg.Debug("select...")
		select {
		case conn, ok := <-acceptChan:
			if ok {
				s.handleConn(conn)
			} else {
				dbg.Debug("failed to accept")
				acceptChan = nil
				return nil
			}
		case <-s.stop:
			dbg.Debug("Stop signal received, stopping.")
			return nil
		}
	}
	return nil
}

func (s *Server) ListenAndServe(port int16) (error, func()) {
	if err := s.listen(port); err != nil {
		return err, nil
	}
	go s.serveLoop()
	return nil, s.Stop
}

func (s *Server) ListenAndServeForever(port int16) error {
	if err, _ := s.ListenAndServe(port); err != nil {
		return err
	}
	s.Wait()
	return nil
}

// Wait for server shutdown
func (s *Server) Wait() {
	dbg.Debug("Waiting for shutdown.")
	<-s.done
}

// Ask for shutdown
func (s *Server) Stop() {
	dbg.Debug("requesting shutdown.")
	s.stop <- true
	close(s.stop)
}

func (s *Server) AddAuthorizedKeys(keyData []byte) {
	for len(keyData) > 0 {
		newKey, _, _, left, err := ssh.ParseAuthorizedKey(keyData)
		keyData = left
		if err != nil {
			dbg.Debug("Error parsing key: %v", err)
			break
		}
		s.AuthorizedKeys[string(newKey.Marshal())] = true
	}
}

func (s *Server) VerifyPublicKey(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	keyStr := string(key.Marshal())
	if _, ok := s.AuthorizedKeys[keyStr]; !ok {
		dbg.Debug("Key not found!")
		return nil, fmt.Errorf("No valid key found.")
	}
	return &ssh.Permissions{}, nil
}

func (s *Server) AddHostkey(keyData []byte) error {
	key, err := ssh.ParsePrivateKey(keyData)
	if err == nil {
		s.ServerConfig.AddHostKey(key)
		return nil
	}
	return err
}

func (s *Server) RandomHostkey() error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	signer, err := ssh.NewSignerFromSigner(key)
	if err != nil {
		return err
	}
	s.ServerConfig.AddHostKey(signer)
	return nil
}
