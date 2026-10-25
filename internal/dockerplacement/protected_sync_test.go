// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package dockerplacement

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"

	"alloyium.local/kernel-poc/internal/hostproto"
)

// sourceCases are host folders every component must judge alike: the review
// found the guard and mounts.py accepting the first group while hostproto
// refused it.
var sourceCases = map[string]bool{
	"/var/backups": false, "/var/log": false, "/var/lib/sudo": false, "/var/lib/sss": false, "/var/lib/agentgate": false,
	"/var/lib/agentgate/secrets": false, "/var/lib/containers/storage": false, "/var/spool/cron": false, "/home/a/.local/bin": false,
	"/var/lib/agentgate-x": false, "/var/lib/agentgate-hostd": false, "/var/lib/agentgate-poc-demo": false, "/home": false, "/home/alice": false,
	"/srv/x/.ssh": false, "/srv/x/.ssh/keys": false, "/data/.local/share/agentgate": false, "/var/lib": false, "/snap/core": false,
	"/var/lib/kubelet/pods": false, "/var/lib/cloud": false, "/etc/ssh": false, "/var": false,
	"/home/alice/src/app": true, "/srv/repos/app": true, "/data/sshkeys-docs": true, "/var/lib/postgresql/16": true, "/opt/tools": true,
	"/srv/local/bin": true, "/srv/agentgate-data": true,
}

// The guard, hostproto and the Python runtime refuse exactly the same host
// folders: the guard calls hostproto.CheckProtectedSource and mounts.py holds
// a block generated from hostproto (internal/hostproto
// TestPythonMountRulesAreGeneratedFromHostproto). This fails if any of the
// three judges a case differently.
func TestEveryCopyOfTheProtectedMountRulesAgrees(t *testing.T) {
	sources := make([]string, 0, len(sourceCases))
	for source, ok := range sourceCases {
		sources = append(sources, source)
		if guard := protectedSource(source) == nil; guard != ok {
			t.Errorf("the guard judges %s %t, want %t", source, guard, ok)
		}
		if proto := hostproto.CheckMountSource(source) == nil; proto != ok {
			t.Errorf("hostproto judges %s %t, want %t", source, proto, ok)
		}
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable; the Python side was not compared")
	}
	script := `import json, sys
sys.path.insert(0, sys.argv[1])
import mounts
out = {}
for source in sys.argv[2:]:
    try:
        mounts.check_bind_source(source)
        out[source] = True
    except mounts.MountError:
        out[source] = False
print(json.dumps(out))`
	raw, err := exec.Command(python, append([]string{"-I", "-c", script, "../../poc/ssh-diagnostic"}, sources...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("python: %v %s", err, raw)
	}
	var judged map[string]bool
	if err = json.Unmarshal(raw, &judged); err != nil {
		t.Fatalf("python output %s", raw)
	}
	for source, ok := range sourceCases {
		if judged[source] != ok {
			t.Errorf("mounts.py judges %s %t, want %t", source, judged[source], ok)
		}
	}
	if !strings.Contains(string(raw), "/srv/repos/app") {
		t.Fatal("the Python side judged nothing")
	}
}
