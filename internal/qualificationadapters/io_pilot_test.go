// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"testing"

	"alloyium.local/kernel-poc/internal/dockerplacement"
	"alloyium.local/kernel-poc/internal/policy"
	"alloyium.local/kernel-poc/internal/qualification"
)

func TestPilotStreamSelectionRequiresTheExactSharedMountAndSignedRights(t *testing.T) {
	path := "/run/agentgate/streams"
	target := dockerplacement.Target{ArtifactPath: path, ArtifactSource: path}
	document := policy.Document{Files: &policy.Files{Rules: []policy.FileRule{{
		ID: "job-streams", Selector: policy.Selector{Kind: "subtree", Path: path},
		Operations: []string{"read", "write"}, Effect: "allow",
	}}}, Network: &policy.Network{Pilot: &policy.PilotNetwork{Mode: "ssh-coding.v1"}}}
	actor := candidateDenial{config: Config{PilotTarget: &target}}
	if got := actor.pilotStreamRoot(document); got != path {
		t.Fatalf("the signed shared stream root was not selected: %q", got)
	}
	for name, change := range map[string]func(*dockerplacement.Target, *policy.Document){
		"different host source": func(t *dockerplacement.Target, _ *policy.Document) { t.ArtifactSource = "/var/lib/agentgate/streams" },
		"missing write":         func(_ *dockerplacement.Target, d *policy.Document) { d.Files.Rules[0].Operations = []string{"read"} },
		"wrong selector":        func(_ *dockerplacement.Target, d *policy.Document) { d.Files.Rules[0].Selector.Kind = "exact" },
		"no pilot":              func(_ *dockerplacement.Target, d *policy.Document) { d.Network.Pilot = nil },
	} {
		t.Run(name, func(t *testing.T) {
			changedTarget := target
			changedDocument := document
			changedFiles := *document.Files
			changedFiles.Rules = append([]policy.FileRule(nil), document.Files.Rules...)
			changedDocument.Files = &changedFiles
			changedNetwork := *document.Network
			changedDocument.Network = &changedNetwork
			change(&changedTarget, &changedDocument)
			changedActor := candidateDenial{config: Config{PilotTarget: &changedTarget}}
			if got := changedActor.pilotStreamRoot(changedDocument); got != "" {
				t.Fatalf("an unbound stream root was selected: %q", got)
			}
		})
	}
}

func TestPilotDescriptorVerifierBindsGeneratedPairToSignedStreamRule(t *testing.T) {
	root := "/run/agentgate/streams"
	request := qualification.Request{Document: policy.Document{Files: &policy.Files{Rules: []policy.FileRule{{
		ID: "job-streams", Selector: policy.Selector{Kind: "subtree", Path: root},
		Operations: []string{"read", "write"}, Effect: "allow",
	}}}, Network: &policy.Network{Pilot: &policy.PilotNetwork{Mode: "ssh-coding.v1"}}}}
	descriptors := []descriptorSnapshot{{Target: root + "/.qualification-Ab12/input", Device: 12, Inode: 100},
		{Target: root + "/.qualification-Ab12/output", Device: 12, Inode: 101}}
	if paths, err := candidateDescriptorTargets(request, descriptors); err != nil || paths[0] != descriptors[0].Target || paths[1] != descriptors[1].Target {
		t.Fatalf("the signed generated pair was rejected: %v", err)
	}
	for name, change := range map[string]func(*qualification.Request, []descriptorSnapshot){
		"foreign directory": func(_ *qualification.Request, d []descriptorSnapshot) {
			d[1].Target = root + "/.qualification-Other/output"
		},
		"foreign mount": func(_ *qualification.Request, d []descriptorSnapshot) {
			d[0].Target = "/var/lib/agentgate/streams/.qualification-Ab12/input"
		},
		"reused inode": func(_ *qualification.Request, d []descriptorSnapshot) { d[1].Inode = d[0].Inode },
		"missing write": func(r *qualification.Request, _ []descriptorSnapshot) {
			r.Document.Files.Rules[0].Operations = []string{"read"}
		},
		"not pilot": func(r *qualification.Request, _ []descriptorSnapshot) { r.Document.Network.Pilot = nil },
	} {
		t.Run(name, func(t *testing.T) {
			changed := request
			files := *request.Document.Files
			files.Rules = append([]policy.FileRule(nil), files.Rules...)
			changed.Document.Files = &files
			network := *request.Document.Network
			changed.Document.Network = &network
			pair := append([]descriptorSnapshot(nil), descriptors...)
			change(&changed, pair)
			if _, err := candidateDescriptorTargets(changed, pair); err == nil {
				t.Fatal("the unbound pair was accepted")
			}
		})
	}
}
