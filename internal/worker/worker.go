// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package worker

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

type Result struct {
	PID                   int  `json:"pid"`
	WorkspaceAllowed      bool `json:"workspace_allowed"`
	OutsideDenied         bool `json:"outside_denied"`
	EndpointAllowed       bool `json:"endpoint_allowed"`
	EndpointDenied        bool `json:"endpoint_denied"`
	WorkspaceDenied       bool `json:"workspace_denied"`
	AllowedEndpointDenied bool `json:"allowed_endpoint_denied"`
}

func writeExisting(path, data string) error {
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_TRUNC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	_, err = syscall.Write(fd, []byte(data))
	return err
}

func connect(port int) error {
	conn, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte("synthetic-worker\n"))
	return err
}

func Attempts(root string, allow, deny int) Result {
	workspaceErr := writeExisting(filepath.Join(root, "workspace/result"), "allowed\n")
	outsideErr := writeExisting(filepath.Join(root, "outside/canary"), "changed\n")
	allowErr := connect(allow)
	denyErr := connect(deny)
	return Result{
		PID:                   os.Getpid(),
		WorkspaceAllowed:      workspaceErr == nil,
		OutsideDenied:         errors.Is(outsideErr, syscall.EPERM),
		EndpointAllowed:       allowErr == nil,
		EndpointDenied:        errors.Is(denyErr, syscall.EPERM),
		WorkspaceDenied:       errors.Is(workspaceErr, syscall.EPERM),
		AllowedEndpointDenied: errors.Is(allowErr, syscall.EPERM),
	}
}

func Run(args []string) error {
	if len(args) != 4 {
		return errors.New("worker requires mode, root, allowed port, denied port")
	}
	allow, err := strconv.Atoi(args[2])
	if err != nil {
		return err
	}
	deny, err := strconv.Atoi(args[3])
	if err != nil {
		return err
	}
	if args[0] == "bootstrap" || args[0] == "expiry" || args[0] == "quarantine" || args[0] == "flood" || args[0] == "read-only" {
		gate := os.NewFile(3, "admission")
		var token [1]byte
		n, err := gate.Read(token[:])
		gate.Close()
		if err != nil || n != 1 || token[0] != 1 {
			return errors.New("admission barrier closed")
		}
		if err = syscall.Setgroups(nil); err != nil {
			return err
		}
		if err = syscall.Setgid(65534); err != nil {
			return err
		}
		if err = syscall.Setuid(65534); err != nil {
			return err
		}
	}
	if args[0] == "flood" {
		for i := 0; i < 10000; i++ {
			if err := writeExisting(filepath.Join(args[1], "outside/canary"), "changed\n"); !errors.Is(err, syscall.EPERM) {
				return errors.New("audit flood fixture bypassed write denial")
			}
		}
		fmt.Println("FLOOD_DENIALS_PASS attempts=10000")
		return nil
	}
	if args[0] == "expiry" {
		time.Sleep(3 * time.Second)
	}
	result := Attempts(args[1], allow, deny)
	if err = json.NewEncoder(os.Stdout).Encode(result); err != nil {
		return err
	}
	if args[0] == "expiry" || args[0] == "quarantine" {
		if result.WorkspaceDenied && result.OutsideDenied && result.AllowedEndpointDenied && result.EndpointDenied {
			return nil
		}
		return errors.New("fail-closed fixture differs from kernel contract")
	}
	if args[0] == "read-only" || args[0] == "child-read-only" {
		if !result.WorkspaceDenied || !result.OutsideDenied || !result.EndpointAllowed || !result.EndpointDenied {
			return errors.New("read-only fixture differs from the admitted policy")
		}
		if args[0] == "child-read-only" {
			return nil
		}
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		child := exec.Command(exe, "worker", "child-read-only", args[1], args[2], args[3])
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		return child.Run()
	}

	if !result.WorkspaceAllowed || !result.OutsideDenied || !result.EndpointAllowed || !result.EndpointDenied {
		return fmt.Errorf("worker effects differ from the kernel contract: %+v", result)
	}
	if args[0] == "bootstrap" {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		child := exec.Command(exe, "worker", "child", args[1], args[2], args[3])
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		return child.Run()
	}
	return nil
}
