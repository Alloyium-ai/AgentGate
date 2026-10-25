// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"database/sql"
	"errors"
	"slices"
	"sort"
	"strings"

	"alloyium.local/kernel-poc/internal/access"
	"alloyium.local/kernel-poc/internal/pocpolicy"
)

// profileApprovalReasons decides whether a launch of profile version v needs a
// second human because of the profile. A profile that requires approval
// always does. One that does not lets a launcher start alone only with the
// exact version an administrator approved (its digest equals
// approved_digest): any other version, including a newer one an editor added,
// needs approval, and the reasons name the drift from the approved version so
// the approver sees what changed.
//
// broker is set for a launch with brokered secrets, whose effective policy
// replaces the taskboard endpoint with the broker (and never mounts the
// bridge), so the taskboard is not listed as something the launch grants.
func (s *Store) profileApprovalReasons(tx *sql.Tx, p Profile, v ProfileVersion, doc pocpolicy.Document, broker bool) ([]string, error) {
	if p.RequireApproval {
		return append([]string{"the profile requires approval"}, policyRiskNotes(doc, nil, broker)...), nil
	}
	if p.ApprovedDigest == "" {
		return append([]string{"no version of profile " + p.Name + " is approved by an administrator for launches without approval"}, policyRiskNotes(doc, nil, broker)...), nil
	}
	if v.Digest == p.ApprovedDigest && v.ID == p.approvedID {
		return nil, nil
	}
	reasons := []string{"profile " + p.Name + " version " + itoa(v.Number) + " (digest " + v.Digest[:12] + ") is not the administrator-approved version " + itoa(p.ApprovedVersion) + " (digest " + p.ApprovedDigest[:12] + ")"}
	approved, err := profileVersionByID(tx, p.approvedID)
	if err != nil {
		return nil, err
	}
	reviewed, err := approved.document()
	if err != nil {
		return nil, err
	}
	return append(reasons, policyRiskNotes(doc, &reviewed, broker)...), nil
}

func profileVersionByID(q queryer, id string) (ProfileVersion, error) {
	var number int
	var profileID string
	if err := q.QueryRow("SELECT profile_id,number FROM profile_versions WHERE id=?", id).Scan(&profileID, &number); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ProfileVersion{}, fail(503, "profile_corrupt", "The approved profile version is missing.")
		}
		return ProfileVersion{}, err
	}
	return profileVersionFrom(q, profileID, number)
}

// The shipped defaults a launch document is measured against
// (internal/access/policy.full.example.json).
var (
	defaultResolvers = []string{"1.1.1.1"}
	defaultTaskboard = pocpolicy.Taskboard{Address: "10.10.10.10", Protocol: "tcp", Port: 8080, TaskID: 1}
	defaultDevices   = []string{"/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"}
	defaultSignals   = []string{"SIGINT", "SIGTERM", "SIGKILL", "SIGHUP", "SIGUSR1", "SIGUSR2", "SIGCONT", "SIGSTOP"}
)

// taskboardBridge is the read-only AF_UNIX bridge a launch receives when its
// policy keeps the taskboard endpoint and grants reading this tree.
const taskboardBridge = "/run/agentgate/taskboard"

// policyRiskNotes lists what doc grants beyond the shipped defaults: DNS
// resolvers other than the default, a taskboard endpoint other than the
// default, the taskboard bridge, anonymous executable memory, devices and
// signals beyond the defaults. With reviewed (the administrator-approved
// version) it also lists every filesystem tree doc grants that reviewed does
// not, and every deny tree reviewed holds that doc dropped. With broker the
// taskboard endpoint and bridge are left out: a broker launch has neither.
func policyRiskNotes(doc pocpolicy.Document, reviewed *pocpolicy.Document, broker bool) []string {
	out := []string{}
	if extra := missing(doc.DNS.Resolvers, defaultResolvers); len(extra) > 0 || len(doc.DNS.Resolvers) == 0 {
		out = append(out, "DNS resolvers other than the default "+strings.Join(defaultResolvers, ", ")+": "+joinOr(doc.DNS.Resolvers))
	}
	if !broker && doc.Taskboard != (pocpolicy.Taskboard{}) && doc.Taskboard != defaultTaskboard {
		out = append(out, "a taskboard endpoint other than the default: "+doc.Taskboard.Protocol+" "+doc.Taskboard.Address+":"+itoa(doc.Taskboard.Port))
	}
	if fs := doc.Filesystem; fs != nil {
		if !broker && doc.Taskboard != (pocpolicy.Taskboard{}) && (slices.Contains(fs.ReadOnly, taskboardBridge) || slices.Contains(fs.Execute, taskboardBridge)) {
			out = append(out, "the taskboard bridge "+taskboardBridge+" (read-only)")
		}
		if fs.Memory.AnonymousExecute {
			out = append(out, "anonymous executable memory (anonymous_execute)")
		}
		if extra := missing(fs.Devices, defaultDevices); len(extra) > 0 {
			out = append(out, "devices beyond the defaults: "+strings.Join(extra, ", "))
		}
	}
	if doc.Process != nil {
		if extra := missing(doc.Process.Signals, defaultSignals); len(extra) > 0 {
			out = append(out, "signals beyond the defaults: "+strings.Join(extra, ", "))
		}
	}
	if reviewed != nil {
		if !slices.Equal(doc.DNS.Resolvers, reviewed.DNS.Resolvers) {
			out = append(out, "DNS resolvers differ from the approved version: "+joinOr(doc.DNS.Resolvers))
		}
		if doc.Taskboard != reviewed.Taskboard {
			out = append(out, "the taskboard endpoint differs from the approved version")
		}
		if !slices.Equal(webList(doc), webList(*reviewed)) {
			out = append(out, "public web access differs from the approved version: "+joinOr(webList(doc)))
		}
		trees := func(d *pocpolicy.Document) map[string][]string {
			m := map[string][]string{}
			if fs := d.Filesystem; fs != nil {
				m["workspace"], m["scratch"], m["read-only"], m["execute"], m["devices"] = []string{fs.Workspace}, fs.Scratch, fs.ReadOnly, fs.Execute, fs.Devices
				m["deny"] = fs.Deny
			}
			if d.Process != nil {
				m["signals"] = d.Process.Signals
			}
			return m
		}
		now, then := trees(&doc), trees(reviewed)
		for _, kind := range []string{"workspace", "scratch", "read-only", "execute", "devices", "signals"} {
			if extra := missing(now[kind], then[kind]); len(extra) > 0 {
				out = append(out, kind+" not in the approved version: "+strings.Join(extra, ", "))
			}
		}
		if removed := missing(then["deny"], now["deny"]); len(removed) > 0 {
			out = append(out, "deny trees removed since the approved version: "+strings.Join(removed, ", "))
		}
		if doc.Filesystem != nil && reviewed.Filesystem != nil && doc.Filesystem.Memory.AnonymousExecute && !reviewed.Filesystem.Memory.AnonymousExecute {
			out = append(out, "anonymous executable memory is new since the approved version")
		}
	}
	return out
}

func webList(d pocpolicy.Document) []string {
	current := access.CurrentWeb(d)
	out := []string{}
	for _, n := range []string{"http", "https", "quic"} {
		if current[n] {
			out = append(out, n)
		}
	}
	return out
}

// missing returns the values of have that are not in base, sorted.
func missing(have, base []string) []string {
	out := []string{}
	for _, v := range have {
		if !slices.Contains(base, v) && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func joinOr(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, ", ")
}
