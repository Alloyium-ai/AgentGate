// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package pocpolicy

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLegacyDocumentsKeepTheTwentyFiveSecondWindowAndDigest(t *testing.T) {
	for _, d := range []Document{fixture(t), fullExample(t)} {
		raw, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), `"mode"`) {
			t.Fatal("a legacy document gained a mode field and so a different digest")
		}
		for _, seconds := range []int{0, 1, 24, 26, 60, 3600} {
			d.DurationSeconds = seconds
			if d.Validate() == nil {
				t.Fatalf("a document without a launch mode accepted duration_seconds %d", seconds)
			}
		}
	}
}

func TestLaunchLifetimeBoundaries(t *testing.T) {
	cases := []struct {
		mode    string
		seconds int
		ok      bool
	}{
		{ModeOneshot, 0, false}, {ModeOneshot, 1, true}, {ModeOneshot, 3600, true}, {ModeOneshot, 3601, false}, {ModeOneshot, -1, false},
		{ModeSession, 59, false}, {ModeSession, 60, true}, {ModeSession, 86400, true}, {ModeSession, 86401, false},
		{"", 25, false}, {"daemon", 60, false}, {"Session", 60, false},
	}
	for _, c := range cases {
		if err := ValidateLifetime(c.mode, c.seconds); (err == nil) != c.ok {
			t.Errorf("%s %d: %v", c.mode, c.seconds, err)
		}
		d := fullExample(t)
		d.Mode, d.DurationSeconds = c.mode, c.seconds
		if c.mode == "" {
			continue
		}
		if err := d.Validate(); (err == nil) != c.ok {
			t.Errorf("document %s %d: %v", c.mode, c.seconds, err)
		}
	}
}

func TestLaunchModeRequiresHostControls(t *testing.T) {
	d := fixture(t)
	d.Mode, d.DurationSeconds = ModeSession, 3600
	if d.Validate() == nil {
		t.Fatal("a version one network-only document accepted a launch mode")
	}
	if _, err := fixture(t).ForLaunch(ModeSession, 3600); err == nil {
		t.Fatal("a version one profile became a launch document")
	}
}

func TestForLaunchBindsModeAndLifetimeIntoTheDigest(t *testing.T) {
	profile := fullExample(t)
	launch, err := profile.ForLaunch(ModeSession, 7200)
	if err != nil {
		t.Fatal(err)
	}
	if launch.Mode != ModeSession || launch.DurationSeconds != 7200 || launch.Digest() == profile.Digest() {
		t.Fatalf("launch document %+v", launch)
	}
	other, _ := profile.ForLaunch(ModeSession, 7201)
	if other.Digest() == launch.Digest() {
		t.Fatal("the lifetime is not bound into the digest")
	}
	// Idempotent for a document that already is that launch document.
	again, err := launch.ForLaunch(ModeSession, 7200)
	if err != nil || again.Digest() != launch.Digest() {
		t.Fatalf("idempotent launch document differs: %v", err)
	}
	if _, err := launch.ForLaunch(ModeOneshot, 7200); err == nil {
		t.Fatal("a session document became a oneshot launch")
	}
	if _, err := launch.ForLaunch(ModeSession, 60); err == nil {
		t.Fatal("a launch document took a different lifetime")
	}
	odd := fullExample(t)
	odd.DurationSeconds = 30
	if _, err := odd.ForLaunch(ModeOneshot, 30); err == nil {
		t.Fatal("an invalid profile document became a launch document")
	}
	// The serialized launch document parses back to the same digest.
	raw, _ := json.Marshal(launch)
	parsed, err := Parse(raw)
	if err != nil || parsed.Digest() != launch.Digest() || !parsed.IsLaunch() {
		t.Fatalf("round trip: %v", err)
	}
}

func TestLaunchDocumentCompilesToItsLifetime(t *testing.T) {
	launch, err := fullExample(t).ForLaunch(ModeSession, 86400)
	if err != nil {
		t.Fatal(err)
	}
	now := uint64(1_000_000_000)
	deadline := now + 86400*1_000_000_000
	compiled, err := launch.Compile(now, deadline)
	if err != nil || compiled.Policy.ExpiresNS != deadline {
		t.Fatalf("compile: %v %d", err, compiled.Policy.ExpiresNS)
	}
	plan, err := launch.FilesystemPlan(7, 1, deadline, network(t, 7))
	if err != nil {
		t.Fatal(err)
	}
	_ = plan
}
