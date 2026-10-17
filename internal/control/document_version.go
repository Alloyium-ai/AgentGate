// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"alloyium.local/kernel-poc/internal/policy"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const documentVersionSchema = `
CREATE TABLE IF NOT EXISTS policy_documents(version_id TEXT PRIMARY KEY REFERENCES versions(id),document TEXT NOT NULL,document_digest TEXT NOT NULL,schema_digest TEXT NOT NULL,compiler_version TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS policy_document_no_update BEFORE UPDATE ON policy_documents BEGIN SELECT RAISE(ABORT,'immutable policy document'); END;
CREATE TRIGGER IF NOT EXISTS policy_document_no_delete BEFORE DELETE ON policy_documents BEGIN SELECT RAISE(ABORT,'immutable policy document'); END;
`

type CreatePolicyDocument struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	ParentID     string `json:"parent_id,omitempty"`
	Format       string `json:"format"`
	Source       string `json:"source"`
	SchemaDigest string `json:"schema_digest"`
	Reason       string `json:"reason"`
}
type DocumentVersion struct {
	Purpose         string          `json:"purpose"`
	Version         Version         `json:"version"`
	Document        policy.Document `json:"document"`
	DocumentDigest  string          `json:"document_digest"`
	SchemaDigest    string          `json:"schema_digest"`
	CompilerVersion string          `json:"compiler_version"`
}
type PolicyPreviewInput struct {
	VersionID    string `json:"version_id"`
	TargetDigest string `json:"target_digest"`
	Node         string `json:"node"`
	Boot         string `json:"boot"`
	Reason       string `json:"reason"`
}

func decodePolicyDocument(data []byte, in *CreatePolicyDocument) error {
	return decodeTargetBody(data, in)
}

func parseDocument(in CreatePolicyDocument) (policy.Document, error) {
	if in.SchemaDigest != policy.SchemaDigest() {
		return policy.Document{}, fail(409, "policy_schema_changed", "Refresh the current policy schema before creating a version.")
	}
	doc, err := policy.Parse([]byte(in.Source), in.Format)
	if err == nil {
		err = doc.CheckDeclaredRequirements()
	}
	if err != nil {
		return policy.Document{}, fail(422, "invalid_policy_document", err.Error())
	}
	return doc, nil
}

func documentBindingDigest(v Version, documentDigest, schemaDigest, compiler string) string {
	return digest([]byte(jsonText(struct {
		Policy   string `json:"policy"`
		Number   int    `json:"number"`
		Parent   string `json:"parent"`
		Document string `json:"document_digest"`
		Schema   string `json:"schema_digest"`
		Compiler string `json:"compiler_version"`
	}{v.PolicyID, v.Number, v.ParentID, documentDigest, schemaDigest, compiler})))
}

func (s *Store) CreatePolicyDocument(op Operation, in CreatePolicyDocument) (any, error) {
	op.Action = "policy.document.created"
	op.Reason = safeReason(in.Reason)
	scope := "policy:write"
	if op.Actor.Kind == "agent" {
		scope = "proposal:create"
	}
	return s.Mutation(op, scope, false, func(tx *sql.Tx, op *Operation) (any, error) {
		if !s.CustomerPolicy {
			return nil, fail(404, "not_found", "Versioned documents require the Community policy contract.")
		}
		if err := reasonValid(in.Reason); err != nil {
			return nil, err
		}
		doc, err := parseDocument(in)
		if err != nil {
			return nil, err
		}
		if len(strings.TrimSpace(in.Name)) < 2 || len(in.Name) > 100 || len(in.Description) > 1000 {
			return nil, fail(422, "invalid_policy", "Supply a policy name and a short description.")
		}
		if op.Actor.Kind == "agent" && in.ParentID == "" {
			return nil, fail(403, "parent_required", "An agent can propose a document only from an existing version.")
		}
		v := Version{ID: newID(), ParentID: in.ParentID, State: "draft", Number: 1, Revision: 1, Actor: op.Actor.Subject, Reason: in.Reason, Created: stamp()}
		if in.ParentID != "" {
			parent, err := versionFrom(tx, in.ParentID)
			if err != nil {
				return nil, err
			}
			v.PolicyID = parent.PolicyID
			var name, description string
			if err = tx.QueryRow("SELECT name,description FROM policies WHERE id=?", v.PolicyID).Scan(&name, &description); err != nil {
				return nil, err
			}
			if strings.TrimSpace(in.Name) != name || in.Description != description {
				return nil, fail(409, "policy_metadata_changed", "A document version must retain its policy name and description.")
			}
			if err = tx.QueryRow("SELECT MAX(number)+1 FROM versions WHERE policy_id=?", v.PolicyID).Scan(&v.Number); err != nil {
				return nil, err
			}
			op.Before = parent
		} else {
			v.PolicyID = newID()
			if _, err = tx.Exec("INSERT INTO policies VALUES(?,?,?,?)", v.PolicyID, strings.TrimSpace(in.Name), in.Description, stamp()); err != nil {
				return nil, err
			}
		}
		if op.Actor.Kind == "agent" {
			v.State = "proposed"
		}
		if doc.Selected != nil {
			v.Rights = Rights{doc.Selected.WorkspaceWrite, doc.Selected.TCPAddress, doc.Selected.TCPPort}
		}
		raw, err := json.Marshal(doc)
		if err != nil {
			return nil, err
		}
		documentDigest := digest(raw)
		v.Digest = documentBindingDigest(v, documentDigest, policy.SchemaDigest(), policy.CompilerVersion)
		if err = insertVersion(tx, v); err != nil {
			return nil, err
		}
		_, err = tx.Exec("INSERT INTO policy_documents VALUES(?,?,?,?,?)", v.ID, string(raw), documentDigest, policy.SchemaDigest(), policy.CompilerVersion)
		if err != nil {
			return nil, err
		}
		op.Resource = v.PolicyID
		op.Version = v.ID
		return DocumentVersion{"contract-draft", v, doc, documentDigest, policy.SchemaDigest(), policy.CompilerVersion}, nil
	})
}

func documentVersionFrom(q queryer, id string) (DocumentVersion, error) {
	var record DocumentVersion
	var source string
	err := q.QueryRow("SELECT document,document_digest,schema_digest,compiler_version FROM policy_documents WHERE version_id=?", id).Scan(&source, &record.DocumentDigest, &record.SchemaDigest, &record.CompilerVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return record, fail(404, "not_found", "This version has no full policy document.")
	}
	if err != nil {
		return record, err
	}
	record.Version, err = versionFrom(q, id)
	if err != nil {
		return record, err
	}
	if record.SchemaDigest != policy.SchemaDigest() || record.CompilerVersion != policy.CompilerVersion {
		return record, fail(409, "policy_contract_changed", "This stored document requires its original schema and compiler.")
	}
	record.Document, err = policy.Parse([]byte(source), "json")
	if err != nil {
		return record, fail(409, "policy_document_changed", "The stored document failed contract validation.")
	}
	if err = record.Document.CheckDeclaredRequirements(); err != nil {
		return record, err
	}
	if digest([]byte(source)) != record.DocumentDigest || record.Version.Digest != documentBindingDigest(record.Version, record.DocumentDigest, record.SchemaDigest, record.CompilerVersion) {
		return record, fail(409, "policy_document_changed", "The stored document differs from its immutable version binding.")
	}
	record.Purpose = "contract-draft"
	return record, nil
}
func (s *Store) PolicyDocument(id string) (DocumentVersion, error) {
	return documentVersionFrom(s.DB, id)
}

func (s *Store) PreviewPolicyDocument(op Operation, in PolicyPreviewInput) (any, error) {
	op.Action = "policy.document.previewed"
	op.Resource = in.VersionID
	op.Version = in.VersionID
	op.Reason = safeReason(in.Reason)
	return s.Mutation(op, "policy:read", false, func(tx *sql.Tx, op *Operation) (any, error) {
		if err := reasonValid(in.Reason); err != nil {
			return nil, err
		}
		if in.Node == "" || in.Boot == "" {
			return nil, fail(422, "invalid_target", "Bind the preview to a node and boot.")
		}
		record, err := documentVersionFrom(tx, in.VersionID)
		if err != nil {
			return nil, err
		}
		target, report, err := verifiedStoredTarget(tx, in.TargetDigest, policy.TargetBinding{Node: in.Node, Boot: in.Boot})
		if err != nil {
			return nil, err
		}
		if op.Actor.Kind != "human" && op.Actor.Subject != report.Subject {
			return nil, fail(403, "forbidden", "A machine can preview only its own target.")
		}
		preview, err := policy.PreviewForTarget(record.Document, target, time.Now().Unix())
		if err != nil {
			return nil, fail(422, "target_unqualified", err.Error())
		}
		return map[string]any{"purpose": "validation-preview", "version_id": record.Version.ID, "version_digest": record.Version.Digest, "preview": preview, "admission_available": false}, nil
	})
}

func rejectDocumentPublication(q queryer, id, state string) error {
	var count int
	if err := q.QueryRow("SELECT count(*) FROM policy_documents WHERE version_id=?", id).Scan(&count); err != nil {
		return err
	}
	if count != 0 && (state == "approved" || state == "published") {
		return fail(422, "kernel_compiler_unqualified", "This document can remain a draft or proposal until the full kernel compiler qualifies.")
	}
	return nil
}
