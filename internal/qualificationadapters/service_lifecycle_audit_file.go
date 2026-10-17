// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"bytes"
	"errors"
	"path/filepath"

	"alloyium.local/kernel-poc/internal/domainstore"
	"alloyium.local/kernel-poc/internal/jobaudit"
)

type serviceLifecycleAuditFile struct {
	Path       string `json:"path"`
	Raw        []byte `json:"raw"`
	SHA256     string `json:"sha256"`
	StartedNS  uint64 `json:"started_mono_ns,string"`
	FinishedNS uint64 `json:"finished_mono_ns,string"`
	Error      string `json:"error"`
	Errno      int    `json:"errno"`
}

func serviceLifecycleAuditPath(scene serviceLifecycleScene) (string, error) {
	root := filepath.Join(scene.Recipe.Spec.OwnedRoot, "private/audit")
	if scene.NodeConfig.AuditRoot != root {
		return "", errors.New("the actual fixture audit root differs")
	}
	binding := scene.Prepared.Record.Binding
	if binding.RunID == "" {
		return "", errors.New("the actual fixture audit binding is absent")
	}
	name, err := domainstore.ReservationName(scene.Recipe.FixtureRoot.OwnedPrefix, binding)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, name+".audit"), nil
}

// Capture runs before owned state removal, including failed execution paths.
// An incomplete file remains raw evidence; it supplies no complete verdict.
func captureServiceLifecycleAudit(scene *serviceLifecycleScene) (err error) {
	file := &serviceLifecycleAuditFile{StartedNS: serviceMono()}
	scene.AuditFile = file
	defer func() {
		file.FinishedNS = serviceMono()
		file.Error = serviceError(err)
		if err != nil {
			file.Errno = serviceLifecycleErrno(err)
		}
	}()
	file.Path, err = serviceLifecycleAuditPath(*scene)
	if err != nil {
		return err
	}
	file.Raw, err = readServiceLifecycleOwned(file.Path, 8<<20)
	if err != nil {
		return err
	}
	file.SHA256 = digestBytes(file.Raw)
	bundle, err := jobaudit.Read(bytes.NewReader(file.Raw))
	scene.Audit = serviceJSON(bundle)
	return err
}

func verifyServiceLifecycleAuditFile(scene serviceLifecycleScene) error {
	file := scene.AuditFile
	if file == nil {
		return nil // Historical receipts retain their original raw bundle only.
	}
	path, err := serviceLifecycleAuditPath(scene)
	if err != nil || file.Path != path || file.Error != "" || file.Errno != 0 || len(file.Raw) == 0 || len(file.Raw) > 8<<20 || file.SHA256 != digestBytes(file.Raw) || file.StartedNS == 0 || file.FinishedNS < file.StartedNS {
		return errors.New("the actual lifecycle audit file custody differs")
	}
	bundle, err := jobaudit.Read(bytes.NewReader(file.Raw))
	if err != nil || !bytes.Equal(serviceJSON(bundle), scene.Audit) {
		return errors.New("the actual audit file and bundle differ")
	}
	return nil
}
