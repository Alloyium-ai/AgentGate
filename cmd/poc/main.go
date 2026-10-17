// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"alloyium.local/kernel-poc/internal/audit"
	"alloyium.local/kernel-poc/internal/grant"
	"alloyium.local/kernel-poc/internal/worker"
	"alloyium.local/kernel-poc/internal/workload"
)

func main() {
	var err error
	if len(os.Args) < 2 {
		err = fmt.Errorf("use probe or worker")
	} else if os.Args[1] == "worker" {
		err = worker.Run(os.Args[2:])
	} else if os.Args[1] == "probe" {
		err = probe(os.Args[2:], false, "bootstrap")
	} else if os.Args[1] == "demo" {
		err = probe(os.Args[2:], true, "bootstrap")
	} else if os.Args[1] == "controlled" {
		err = controlled(os.Args[2:])
	} else if os.Args[1] == "run" {
		err = runWorkload(os.Args[2:])
	} else if os.Args[1] == "workload-child" && len(os.Args) == 2 {
		err = workload.Child()
	} else if os.Args[1] == "keys" && len(os.Args) == 3 {
		err = nodeKeys(os.Args[2])
	} else if os.Args[1] == "request" {
		err = requestWorkload(os.Args[2:])
	} else if os.Args[1] == "quarantine" {
		err = probe(os.Args[2:], false, "quarantine")
	} else if os.Args[1] == "loss" {
		err = probe(os.Args[2:], true, "flood")
	} else if os.Args[1] == "crash" {
		err = crash(os.Args[2:])
	} else if os.Args[1] == "recover" {
		err = recoverRun(os.Args[2:])
	} else if os.Args[1] == "init" && len(os.Args) == 3 {
		err = grant.Init(os.Args[2])
	} else if os.Args[1] == "verify" && len(os.Args) == 4 {
		var trust grant.Trust
		var data []byte
		data, err = os.ReadFile(os.Args[3])
		if err == nil {
			err = json.Unmarshal(data, &trust)
		}
		if err == nil {
			var verdict string
			verdict, err = audit.Verify(os.Args[2], trust)
			fmt.Println(verdict)
		}
	} else {
		err = fmt.Errorf("unknown command")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
