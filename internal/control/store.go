// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const schema = `
CREATE TABLE IF NOT EXISTS policies(id TEXT PRIMARY KEY,name TEXT NOT NULL,description TEXT NOT NULL,created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS versions(id TEXT PRIMARY KEY,policy_id TEXT NOT NULL REFERENCES policies(id),number INTEGER NOT NULL,parent_id TEXT NOT NULL,state TEXT NOT NULL,rights TEXT NOT NULL,digest TEXT NOT NULL,revision INTEGER NOT NULL,actor TEXT NOT NULL,reason TEXT NOT NULL,created TEXT NOT NULL,UNIQUE(policy_id,number));
CREATE TRIGGER IF NOT EXISTS version_content_immutable BEFORE UPDATE OF id,policy_id,number,parent_id,rights,digest,actor,reason,created ON versions BEGIN SELECT RAISE(ABORT,'immutable policy content'); END;
CREATE TRIGGER IF NOT EXISTS version_no_delete BEFORE DELETE ON versions BEGIN SELECT RAISE(ABORT,'immutable policy version'); END;
CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY,agent_id TEXT NOT NULL,requested_version TEXT NOT NULL REFERENCES versions(id),approved_version TEXT NOT NULL,state TEXT NOT NULL,reason TEXT NOT NULL,decision_reason TEXT NOT NULL,decided_by TEXT NOT NULL,revision INTEGER NOT NULL,created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS admissions(id TEXT PRIMARY KEY,request_id TEXT NOT NULL UNIQUE REFERENCES requests(id),agent_id TEXT NOT NULL,run_id TEXT NOT NULL UNIQUE,node TEXT NOT NULL,boot TEXT NOT NULL,domain TEXT NOT NULL,version_id TEXT NOT NULL REFERENCES versions(id),policy_digest TEXT NOT NULL,token TEXT NOT NULL,grant_digest TEXT NOT NULL,state TEXT NOT NULL,created TEXT NOT NULL,expires TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS activations(admission_id TEXT PRIMARY KEY REFERENCES admissions(id),version_id TEXT NOT NULL,policy_digest TEXT NOT NULL,bpf_digest TEXT NOT NULL,node_subject TEXT NOT NULL,time TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS activation_no_update BEFORE UPDATE ON activations BEGIN SELECT RAISE(ABORT,'immutable activation'); END;
CREATE TRIGGER IF NOT EXISTS activation_no_delete BEFORE DELETE ON activations BEGIN SELECT RAISE(ABORT,'immutable activation'); END;
CREATE TRIGGER IF NOT EXISTS admission_binding_immutable BEFORE UPDATE OF request_id,agent_id,run_id,node,boot,domain,version_id,policy_digest,token,grant_digest,created,expires ON admissions BEGIN SELECT RAISE(ABORT,'immutable admission binding'); END;
CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY,admission_id TEXT NOT NULL UNIQUE REFERENCES admissions(id),agent_id TEXT NOT NULL,version_id TEXT NOT NULL,policy_digest TEXT NOT NULL,verifier TEXT NOT NULL,evidence_digest TEXT NOT NULL,evidence TEXT NOT NULL,created TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS run_no_update BEFORE UPDATE ON runs BEGIN SELECT RAISE(ABORT,'immutable execution evidence'); END;
CREATE TRIGGER IF NOT EXISTS run_no_delete BEFORE DELETE ON runs BEGIN SELECT RAISE(ABORT,'immutable execution evidence'); END;
CREATE TABLE IF NOT EXISTS services(subject TEXT PRIMARY KEY,kind TEXT NOT NULL,public_key TEXT NOT NULL,scopes TEXT NOT NULL,node TEXT NOT NULL,enabled INTEGER NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS one_service_per_node ON services(node) WHERE kind='service';
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT,time TEXT NOT NULL,actor TEXT NOT NULL,actor_kind TEXT NOT NULL,action TEXT NOT NULL,resource TEXT NOT NULL,version TEXT NOT NULL,run TEXT NOT NULL,before_json TEXT NOT NULL,after_json TEXT NOT NULL,reason TEXT NOT NULL,request_id TEXT NOT NULL,correlation_id TEXT NOT NULL,result TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT,'append-only audit'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT,'append-only audit'); END;
CREATE TABLE IF NOT EXISTS idempotency(actor TEXT NOT NULL,action TEXT NOT NULL,key TEXT NOT NULL,digest TEXT NOT NULL,response TEXT NOT NULL,PRIMARY KEY(actor,action,key));
CREATE TABLE IF NOT EXISTS nonces(actor TEXT NOT NULL,nonce TEXT NOT NULL,time TEXT NOT NULL,PRIMARY KEY(actor,nonce));
CREATE TABLE IF NOT EXISTS login_states(state_hash TEXT PRIMARY KEY,nonce TEXT NOT NULL,verifier TEXT NOT NULL,binding_hash TEXT NOT NULL,expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(id_hash TEXT PRIMARY KEY,actor TEXT NOT NULL,csrf TEXT NOT NULL,expires INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS audit_actor_time ON audit(actor,time,id);
CREATE INDEX IF NOT EXISTS audit_resource_time ON audit(resource,time,id);
CREATE INDEX IF NOT EXISTS audit_run_action_time ON audit(run,action,time,id);
CREATE INDEX IF NOT EXISTS versions_policy_state ON versions(policy_id,state,number);
CREATE INDEX IF NOT EXISTS requests_agent_state ON requests(agent_id,state,created);
CREATE INDEX IF NOT EXISTS admissions_agent_state ON admissions(agent_id,state,created);
CREATE INDEX IF NOT EXISTS runs_agent_policy ON runs(agent_id,version_id,created);
PRAGMA user_version=1;`

type Store struct {
	DB                 *sql.DB
	Authority          ed25519.PrivateKey
	mu                 sync.Mutex
	Changed            func(int64)
	ResolveRoles       func([]string) []string
	CheckConfiguration func() error
	LoginAuthority     string
	LocalIdentity      bool
	CustomerPolicy     bool
	// JobKey signs every host job. It is separate from Authority so it can be
	// rotated without changing the application authority.
	JobKey ed25519.PrivateKey
	// Provisioning holds the job queue timing; zero values use the defaults.
	Provisioning ProvisioningConfig
	// Now is the clock; tests replace it.
	Now func() time.Time
	// rejectedSealKeys remembers the digest of the last seal key record each
	// host sent that did not verify, so it is audited once, not every poll.
	// Guarded by mu (host requests hold it).
	rejectedSealKeys map[string]string
	// denials samples anonymous denial audit rows per source and minute
	// (denial_sampling.go). Guarded by mu.
	denials map[string]*denialWindow
}

func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	_, dbErr := os.Stat(filepath.Join(dir, "control.db"))
	existing := dbErr == nil
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "control.db")+"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=temp_store(MEMORY)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	s := &Store{DB: db}
	if err = s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	name := filepath.Join(dir, "authority.key")
	key, err := os.ReadFile(name)
	if os.IsNotExist(err) {
		if existing {
			db.Close()
			return nil, errors.New("existing database lacks its pinned authority key")
		}
		_, key, err = ed25519.GenerateKey(rand.Reader)
		if err == nil {
			var f *os.File
			f, err = os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err == nil {
				_, err = f.Write(key)
				if err == nil {
					err = f.Sync()
				}
				f.Close()
			}
		}
	}
	if err != nil || len(key) != ed25519.PrivateKeySize {
		db.Close()
		return nil, errors.New("authority key unavailable")
	}
	info, err := os.Stat(name)
	if err != nil || info.Mode().Perm() != 0600 {
		db.Close()
		return nil, errors.New("authority key permissions differ")
	}
	s.Authority, err = verifiedAuthority(key)
	if err != nil {
		db.Close()
		return nil, err
	}
	if err = s.loadJobKey(dir); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}
func (s *Store) migrate() error {
	var version int
	if err := s.DB.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version > SchemaVersion {
		return errors.New("unsupported database schema")
	}
	if version == SchemaVersion {
		return nil
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if version < 4 {
		if version == 0 {
			if _, err = tx.Exec(schema); err != nil {
				return err
			}
		}
		if _, err = tx.Exec(`CREATE INDEX IF NOT EXISTS audit_action_time ON audit(action,time,id); CREATE INDEX IF NOT EXISTS audit_time ON audit(time,id); CREATE INDEX IF NOT EXISTS audit_version_time ON audit(version,time,id); PRAGMA user_version=2;`); err != nil {
			return err
		}
		if _, err = tx.Exec(localUserSchema + ` PRAGMA user_version=3;`); err != nil {
			return err
		}
		if _, err = tx.Exec(targetReportSchema + documentVersionSchema + ` PRAGMA user_version=4;`); err != nil {
			return err
		}
		if _, err = appendAudit(tx, Operation{Actor: Actor{Subject: "deployment", Kind: "system"}, Action: "schema.migrated", Resource: "database", Reason: "Migrate schema to version 4", RequestID: "migration-4"}, "committed"); err != nil {
			return err
		}
	}
	if version < 5 {
		if _, err = tx.Exec(provisioningSchema + ` PRAGMA user_version=5;`); err != nil {
			return err
		}
		if _, err = appendAudit(tx, Operation{Actor: Actor{Subject: "deployment", Kind: "system"}, Action: "schema.migrated", Resource: "database", Reason: "Migrate schema to version 5", RequestID: "migration-5"}, "committed"); err != nil {
			return err
		}
	}
	if version < 6 {
		for _, c := range brokerColumns {
			if err = addColumn(tx, c.table, c.column, c.decl); err != nil {
				return err
			}
		}
		if _, err = tx.Exec(brokerTriggers + ` PRAGMA user_version=6;`); err != nil {
			return err
		}
		if _, err = appendAudit(tx, Operation{Actor: Actor{Subject: "deployment", Kind: "system"}, Action: "schema.migrated", Resource: "database", Reason: "Migrate schema to version 6", RequestID: "migration-6"}, "committed"); err != nil {
			return err
		}
	}
	if version < 7 {
		for _, c := range retirementColumns {
			if err = addColumn(tx, c.table, c.column, c.decl); err != nil {
				return err
			}
		}
		if _, err = tx.Exec(`PRAGMA user_version=7;`); err != nil {
			return err
		}
		if _, err = appendAudit(tx, Operation{Actor: Actor{Subject: "deployment", Kind: "system"}, Action: "schema.migrated", Resource: "database", Reason: "Migrate schema to version 7", RequestID: "migration-7"}, "committed"); err != nil {
			return err
		}
	}
	for _, step := range laterMigrations {
		if version >= step.version {
			continue
		}
		for _, c := range step.columns {
			if err = addColumn(tx, c.table, c.column, c.decl); err != nil {
				return err
			}
		}
		if _, err = tx.Exec(step.statements + fmt.Sprintf(" PRAGMA user_version=%d;", step.version)); err != nil {
			return err
		}
		if step.after != nil {
			if err = step.after(tx); err != nil {
				return err
			}
		}
		if _, err = appendAudit(tx, Operation{Actor: Actor{Subject: "deployment", Kind: "system"}, Action: "schema.migrated", Resource: "database", Reason: fmt.Sprintf("Migrate schema to version %d", step.version), RequestID: fmt.Sprintf("migration-%d", step.version)}, "committed"); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// addColumn adds one column unless the table already has it, so a migration
// step can run again (for example after a restore) without failing.
func addColumn(tx *sql.Tx, table, column, decl string) error {
	rows, err := tx.Query("SELECT name FROM pragma_table_info(?)", table)
	if err != nil {
		return err
	}
	exists := false
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		exists = exists || name == column
	}
	rows.Close()
	if err = rows.Err(); err != nil || exists {
		return err
	}
	_, err = tx.Exec("ALTER TABLE " + table + " ADD COLUMN " + column + " " + decl)
	return err
}
func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", b)
}
func appendAudit(tx *sql.Tx, op Operation, result string) (int64, error) {
	row, err := tx.Exec(`INSERT INTO audit(time,actor,actor_kind,action,resource,version,run,before_json,after_json,reason,request_id,correlation_id,result) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, stamp(), op.Actor.Subject, op.Actor.Kind, op.Action, op.Resource, op.Version, op.Run, auditJSON(op.Before), auditJSON(op.After), op.Reason, op.RequestID, op.CorrelationID, result)
	if err != nil {
		return 0, err
	}
	return row.LastInsertId()
}
func auditJSON(value any) string {
	var v any
	json.Unmarshal([]byte(jsonText(value)), &v)
	return jsonText(scrub(v))
}
func scrub(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			switch k {
			case "verifier":
				verdict, ok := val.(string)
				if !ok || (verdict != "VALID_COMPLETE" && verdict != "INCOMPLETE" && verdict != "TAMPERED" && verdict != "UNKNOWN_KEY") {
					x[k] = "[redacted]"
				}
			case "grant", "client_secret", "private_key", "id_token", "access_token", "csrf_token", "pkce_verifier", "session", "proof", "password", "password_hash", "salt", "token", "api_token", "enrollment_token", "ciphertext", "token_hash":
				x[k] = "[redacted]"
			default:
				x[k] = scrub(val)
			}
		}
	case []any:
		for i := range x {
			x[i] = scrub(x[i])
		}
	}
	return v
}
func (s *Store) Denied(op Operation, cause error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = retainDeniedNonce(tx, op); err != nil {
		return err
	}
	write, err := s.sampleDenial(tx, op)
	if err != nil {
		return err
	}
	if !write {
		return tx.Commit()
	}
	_, code, _ := errorResult(cause)
	op.After = map[string]string{"error_code": code}
	id, err := appendAudit(tx, op, "denied")
	if err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	s.notify(id)
	return nil
}
func (s *Store) notify(id int64) {
	if s.Changed != nil {
		s.Changed(id)
	}
}
func (s *Store) Mutation(op Operation, scope string, human bool, fn func(*sql.Tx, *Operation) (any, error)) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.DB.BeginTx(context.Background(), nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = s.authorize(tx, &op, scope, human); err != nil {
		return s.deniedLocked(tx, op, err)
	}
	if op.ProofNonce != "" {
		if _, err = tx.Exec("INSERT INTO nonces VALUES(?,?,?)", op.Actor.Subject, op.ProofNonce, stamp()); err != nil {
			return s.deniedLocked(tx, op, fail(409, "proof_replay", "The signed request proof already exists."))
		}
	}
	if op.Revalidate != nil {
		if err = op.Revalidate(tx); err != nil {
			return s.deniedLocked(tx, op, err)
		}
	}
	if op.Idempotency != "" {
		var oldDigest, response string
		e := tx.QueryRow("SELECT digest,response FROM idempotency WHERE actor=? AND action=? AND key=?", op.Actor.Subject, op.Action, op.Idempotency).Scan(&oldDigest, &response)
		if e == nil {
			if oldDigest != op.BodyDigest {
				return s.deniedLocked(tx, op, fail(409, "idempotency_conflict", "This key identifies a different request."))
			}
			if op.RevalidateCached != nil {
				if err = op.RevalidateCached(tx, response); err != nil {
					return s.deniedLocked(tx, op, err)
				}
			}
			if err = s.authorize(tx, &op, scope, human); err != nil {
				return s.deniedLocked(tx, op, err)
			}
			var value any
			json.Unmarshal([]byte(response), &value)
			op.Action += ".replayed"
			op.After = map[string]string{"idempotency": "matched"}
			id, e := appendAudit(tx, op, "replayed")
			if e != nil {
				return nil, e
			}
			if e = s.authorize(tx, &op, scope, human); e != nil {
				return s.deniedLocked(tx, op, e)
			}
			if e = tx.Commit(); e != nil {
				return nil, e
			}
			s.notify(id)
			return value, nil
		}
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return nil, e
		}
	}
	value, err := fn(tx, &op)
	if err != nil {
		return s.deniedLocked(tx, op, err)
	}
	if op.Action != "auth.logout" {
		if err = s.authorize(tx, &op, scope, human); err != nil {
			return s.deniedLocked(tx, op, err)
		}
	}
	op.After = value
	id, err := appendAudit(tx, op, "committed")
	if err != nil {
		return nil, err
	}
	if op.Idempotency != "" {
		if _, err = tx.Exec("INSERT INTO idempotency VALUES(?,?,?,?,?)", op.Actor.Subject, op.Action, op.Idempotency, op.BodyDigest, jsonText(value)); err != nil {
			return nil, err
		}
	}
	if op.Action != "auth.logout" {
		if err = s.authorize(tx, &op, scope, human); err != nil {
			return s.deniedLocked(tx, op, err)
		}
	}
	if op.Action == "auth.logout" && s.CheckConfiguration != nil {
		if err = s.CheckConfiguration(); err != nil {
			return s.deniedLocked(tx, op, err)
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	s.notify(id)
	return value, nil
}
func (s *Store) deniedLocked(tx *sql.Tx, op Operation, cause error) (any, error) {
	tx.Rollback()
	next, err := s.DB.Begin()
	if err != nil {
		return nil, err
	}
	defer next.Rollback()
	if err = retainDeniedNonce(next, op); err != nil {
		return nil, err
	}
	_, code, _ := errorResult(cause)
	op.Before = nil
	op.After = map[string]string{"error_code": code}
	id, err := appendAudit(next, op, "denied")
	if err != nil {
		return nil, err
	}
	if err = next.Commit(); err != nil {
		return nil, err
	}
	s.notify(id)
	return nil, cause
}
