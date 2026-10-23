// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package main

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"

	"alloyium.local/kernel-poc/internal/policy"
	"alloyium.local/kernel-poc/internal/testpolicy"
)

// diagnosticPolicy creates setup input only. It cannot grant normal admission.
func diagnosticPolicy(host, rawIP string, port, taskID int) (policy.Document, error) {
	d := testpolicy.Deny()
	ip, err := netip.ParseAddr(rawIP)
	if err != nil || !ip.IsPrivate() || ip.Is4In6() || ip.String() != rawIP ||
		port < 1 || port > 65535 || taskID < 1 {
		return d, errors.New("a canonical private taskboard IP, port and task ID are required")
	}
	family := "ipv4"
	if ip.Is6() {
		family = "ipv6"
	}
	d.Network.Pilot = &policy.PilotNetwork{Mode: "ssh-coding.v1", TaskboardIP: rawIP, TaskboardPort: port, TaskboardTaskID: taskID}
	d.Network.Rules = []policy.NetworkRule{
		{ID: "public-https", Family: "ipv4", Protocol: "tcp", Destination: policy.Destination{Kind: "hostname", Value: host}, PortFrom: 443, PortTo: 443, Effect: "allow"},
		{ID: "taskboard", Family: family, Protocol: "tcp", Destination: policy.Destination{Kind: "ip", Value: rawIP}, PortFrom: port, PortTo: port, Effect: "allow"},
	}
	d.Lifecycle.DurationSeconds = 30
	d.RequiredCapabilities, err = policy.Requirements(d)
	if err != nil {
		return d, err
	}
	return d, d.Validate()
}

func policyCommand(args []string) error {
	if len(args) == 2 && args[0] == "policy-digest" {
		raw, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		d, err := policy.Parse(raw, "json")
		if err != nil {
			return err
		}
		digest, err := d.Digest()
		if err == nil {
			fmt.Println(digest)
		}
		return err
	}
	if len(args) != 5 || args[0] != "policy" {
		return errors.New("usage: pilot-network-diagnostic policy HOST PRIVATE_IP PORT TASK_ID; policy-digest FILE")
	}
	port, err := strconv.Atoi(args[3])
	if err != nil {
		return err
	}
	taskID, err := strconv.Atoi(args[4])
	if err != nil {
		return err
	}
	d, err := diagnosticPolicy(args[1], args[2], port, taskID)
	if err != nil {
		return err
	}
	raw, err := d.Canonical()
	if err == nil {
		_, err = os.Stdout.Write(append(raw, '\n'))
	}
	return err
}
