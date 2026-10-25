// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import "database/sql"

// SchemaVersion is the database user_version this build writes.
const SchemaVersion = 10

// provisioningSchema adds targets, profiles, launches, jobs, secrets metadata
// and API tokens. Every statement is idempotent. Bindings that the contract
// calls immutable are guarded by triggers, so even a buggy caller cannot
// rewrite them.
const provisioningSchema = `
CREATE TABLE IF NOT EXISTS job_keys(key_id TEXT PRIMARY KEY,public_key TEXT NOT NULL,created TEXT NOT NULL,retired TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS job_key_immutable BEFORE UPDATE OF key_id,public_key,created ON job_keys BEGIN SELECT RAISE(ABORT,'immutable job key'); END;
CREATE TRIGGER IF NOT EXISTS job_key_no_delete BEFORE DELETE ON job_keys BEGIN SELECT RAISE(ABORT,'append-only job keys'); END;

CREATE TABLE IF NOT EXISTS targets(id TEXT PRIMARY KEY,name TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('pending','awaiting_key_approval','active','rekey_required','retired')),capabilities TEXT NOT NULL,hostname TEXT NOT NULL,agent_version TEXT NOT NULL,host_key TEXT NOT NULL,host_key_id TEXT NOT NULL,encryption_key TEXT NOT NULL,job_key_id TEXT NOT NULL,last_sequence INTEGER NOT NULL,last_seen INTEGER NOT NULL,heartbeat_seconds INTEGER NOT NULL,created TEXT NOT NULL,created_by TEXT NOT NULL,updated TEXT NOT NULL,revision INTEGER NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS targets_live_name ON targets(name) WHERE state<>'retired';
CREATE TRIGGER IF NOT EXISTS target_identity_immutable BEFORE UPDATE OF id,created,created_by ON targets BEGIN SELECT RAISE(ABORT,'immutable target identity'); END;
CREATE TRIGGER IF NOT EXISTS target_retired_final BEFORE UPDATE ON targets WHEN OLD.state='retired' BEGIN SELECT RAISE(ABORT,'retired target'); END;
CREATE TRIGGER IF NOT EXISTS target_no_delete BEFORE DELETE ON targets BEGIN SELECT RAISE(ABORT,'retire a target instead of deleting it'); END;

CREATE TABLE IF NOT EXISTS enrollment_tokens(token_hash TEXT PRIMARY KEY,target_id TEXT NOT NULL REFERENCES targets(id),expires INTEGER NOT NULL,used INTEGER NOT NULL,created TEXT NOT NULL,created_by TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS enrollment_token_single_use BEFORE UPDATE ON enrollment_tokens WHEN OLD.used<>0 BEGIN SELECT RAISE(ABORT,'used enrollment token'); END;

CREATE TABLE IF NOT EXISTS hostd_keys(target_id TEXT NOT NULL REFERENCES targets(id),key_id TEXT NOT NULL,public_key TEXT NOT NULL,encryption_key TEXT NOT NULL,bound TEXT NOT NULL,retired TEXT NOT NULL,PRIMARY KEY(target_id,key_id));
CREATE TRIGGER IF NOT EXISTS hostd_key_immutable BEFORE UPDATE OF target_id,key_id,public_key,encryption_key,bound ON hostd_keys BEGIN SELECT RAISE(ABORT,'immutable host key binding'); END;
CREATE TRIGGER IF NOT EXISTS hostd_key_no_delete BEFORE DELETE ON hostd_keys BEGIN SELECT RAISE(ABORT,'append-only host keys'); END;

CREATE TABLE IF NOT EXISTS host_nonces(target_id TEXT NOT NULL,nonce TEXT NOT NULL,time INTEGER NOT NULL,PRIMARY KEY(target_id,nonce));
CREATE INDEX IF NOT EXISTS host_nonces_time ON host_nonces(time);
CREATE TABLE IF NOT EXISTS host_heartbeats(id INTEGER PRIMARY KEY AUTOINCREMENT,target_id TEXT NOT NULL,time INTEGER NOT NULL,sequence INTEGER NOT NULL,heartbeat TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS host_heartbeats_target ON host_heartbeats(target_id,id);

CREATE TABLE IF NOT EXISTS profiles(id TEXT PRIMARY KEY,name TEXT NOT NULL UNIQUE,description TEXT NOT NULL,require_approval INTEGER NOT NULL,created TEXT NOT NULL,created_by TEXT NOT NULL,revision INTEGER NOT NULL);
CREATE TRIGGER IF NOT EXISTS profile_identity_immutable BEFORE UPDATE OF id,name,created,created_by ON profiles BEGIN SELECT RAISE(ABORT,'immutable profile identity'); END;
CREATE TRIGGER IF NOT EXISTS profile_no_delete BEFORE DELETE ON profiles BEGIN SELECT RAISE(ABORT,'immutable profile'); END;
CREATE TABLE IF NOT EXISTS profile_versions(id TEXT PRIMARY KEY,profile_id TEXT NOT NULL REFERENCES profiles(id),number INTEGER NOT NULL,parent_id TEXT NOT NULL,document TEXT NOT NULL,digest TEXT NOT NULL,edits TEXT NOT NULL,actor TEXT NOT NULL,reason TEXT NOT NULL,created TEXT NOT NULL,UNIQUE(profile_id,number));
CREATE TRIGGER IF NOT EXISTS profile_version_no_update BEFORE UPDATE ON profile_versions BEGIN SELECT RAISE(ABORT,'immutable profile version'); END;
CREATE TRIGGER IF NOT EXISTS profile_version_no_delete BEFORE DELETE ON profile_versions BEGIN SELECT RAISE(ABORT,'immutable profile version'); END;

CREATE TABLE IF NOT EXISTS secrets(id TEXT PRIMARY KEY,name TEXT NOT NULL,target_id TEXT NOT NULL REFERENCES targets(id),upstreams TEXT NOT NULL,header TEXT NOT NULL,fingerprint TEXT NOT NULL,allowed_profiles TEXT NOT NULL,allowed_launchers TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('pending','stored','failed','deleting','deleted')),created TEXT NOT NULL,created_by TEXT NOT NULL,updated TEXT NOT NULL,revision INTEGER NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS secrets_live_name ON secrets(target_id,name) WHERE state NOT IN ('failed','deleted');
CREATE TRIGGER IF NOT EXISTS secret_binding_immutable BEFORE UPDATE OF id,name,target_id,upstreams,header,fingerprint,allowed_profiles,allowed_launchers,created,created_by ON secrets BEGIN SELECT RAISE(ABORT,'immutable secret metadata'); END;
CREATE TRIGGER IF NOT EXISTS secret_no_delete BEFORE DELETE ON secrets BEGIN SELECT RAISE(ABORT,'append-only secret metadata'); END;

CREATE TABLE IF NOT EXISTS launch_specs(digest TEXT PRIMARY KEY,canonical TEXT NOT NULL,created TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS launch_spec_no_update BEFORE UPDATE ON launch_specs BEGIN SELECT RAISE(ABORT,'immutable launch spec'); END;
CREATE TRIGGER IF NOT EXISTS launch_spec_no_delete BEFORE DELETE ON launch_specs BEGIN SELECT RAISE(ABORT,'immutable launch spec'); END;

CREATE TABLE IF NOT EXISTS launches(id TEXT PRIMARY KEY,name TEXT NOT NULL,spec_digest TEXT NOT NULL REFERENCES launch_specs(digest),target_id TEXT NOT NULL REFERENCES targets(id),profile_version_id TEXT NOT NULL,policy TEXT NOT NULL,policy_digest TEXT NOT NULL,plan TEXT NOT NULL,mode TEXT NOT NULL,lifetime_seconds INTEGER NOT NULL,approval_required INTEGER NOT NULL,state TEXT NOT NULL,requested_by TEXT NOT NULL,decided_by TEXT NOT NULL,decision_reason TEXT NOT NULL,stop_reason TEXT NOT NULL,terminal_reason TEXT NOT NULL,evidence_missing TEXT NOT NULL,receipt TEXT NOT NULL,kernel_verified INTEGER NOT NULL CHECK(kernel_verified=0),created TEXT NOT NULL,updated TEXT NOT NULL,queued_at TEXT NOT NULL,expires_at INTEGER NOT NULL,started_at TEXT NOT NULL,ended_at TEXT NOT NULL,event_seq INTEGER NOT NULL,log_seq INTEGER NOT NULL,log_bytes INTEGER NOT NULL,revision INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS launches_state ON launches(state,created);
CREATE INDEX IF NOT EXISTS launches_target_state ON launches(target_id,state);
CREATE TRIGGER IF NOT EXISTS launch_binding_immutable BEFORE UPDATE OF id,name,spec_digest,target_id,profile_version_id,policy,policy_digest,plan,mode,lifetime_seconds,approval_required,requested_by,created ON launches BEGIN SELECT RAISE(ABORT,'immutable launch binding'); END;
CREATE TRIGGER IF NOT EXISTS launch_receipt_once BEFORE UPDATE OF receipt ON launches WHEN OLD.receipt<>'' AND NEW.receipt<>OLD.receipt BEGIN SELECT RAISE(ABORT,'immutable launch receipt'); END;
CREATE TRIGGER IF NOT EXISTS launch_terminal_final BEFORE UPDATE OF state ON launches WHEN OLD.state IN ('stopped','expired','failed','rejected','cancelled') AND NEW.state<>OLD.state BEGIN SELECT RAISE(ABORT,'terminal launch'); END;
CREATE TRIGGER IF NOT EXISTS launch_no_delete BEFORE DELETE ON launches BEGIN SELECT RAISE(ABORT,'immutable launch'); END;

CREATE TABLE IF NOT EXISTS launch_events(launch_id TEXT NOT NULL REFERENCES launches(id),seq INTEGER NOT NULL,time TEXT NOT NULL,kind TEXT NOT NULL,from_state TEXT NOT NULL,to_state TEXT NOT NULL,actor TEXT NOT NULL,reason TEXT NOT NULL,data TEXT NOT NULL,PRIMARY KEY(launch_id,seq));
CREATE TRIGGER IF NOT EXISTS launch_event_no_update BEFORE UPDATE ON launch_events BEGIN SELECT RAISE(ABORT,'append-only launch events'); END;
CREATE TRIGGER IF NOT EXISTS launch_event_no_delete BEFORE DELETE ON launch_events BEGIN SELECT RAISE(ABORT,'append-only launch events'); END;
CREATE TABLE IF NOT EXISTS launch_logs(launch_id TEXT NOT NULL REFERENCES launches(id),seq INTEGER NOT NULL,time INTEGER NOT NULL,stream TEXT NOT NULL,text TEXT NOT NULL,PRIMARY KEY(launch_id,seq));
CREATE TRIGGER IF NOT EXISTS launch_log_no_update BEFORE UPDATE ON launch_logs BEGIN SELECT RAISE(ABORT,'append-only launch logs'); END;

CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,type TEXT NOT NULL,target_id TEXT NOT NULL REFERENCES targets(id),launch_id TEXT NOT NULL,secret_id TEXT NOT NULL,spec_digest TEXT NOT NULL,policy_digest TEXT NOT NULL,key_id TEXT NOT NULL,envelope TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('queued','delivered','succeeded','failed','rejected','expired','cancelled')),attempts INTEGER NOT NULL,created TEXT NOT NULL,deadline INTEGER NOT NULL,delivered INTEGER NOT NULL,completed TEXT NOT NULL,result TEXT NOT NULL,event_seq INTEGER NOT NULL,revision INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS jobs_target_state ON jobs(target_id,state,created);
CREATE INDEX IF NOT EXISTS jobs_launch ON jobs(launch_id,type);
CREATE TRIGGER IF NOT EXISTS job_binding_immutable BEFORE UPDATE OF id,type,target_id,launch_id,secret_id,spec_digest,policy_digest,key_id,created,deadline ON jobs BEGIN SELECT RAISE(ABORT,'immutable job binding'); END;
CREATE TRIGGER IF NOT EXISTS job_result_once BEFORE UPDATE OF result ON jobs WHEN OLD.result<>'' AND NEW.result<>OLD.result BEGIN SELECT RAISE(ABORT,'immutable job result'); END;
CREATE TRIGGER IF NOT EXISTS job_no_delete BEFORE DELETE ON jobs BEGIN SELECT RAISE(ABORT,'append-only jobs'); END;
CREATE TABLE IF NOT EXISTS job_events(job_id TEXT NOT NULL REFERENCES jobs(id),seq INTEGER NOT NULL,digest TEXT NOT NULL,event TEXT NOT NULL,time TEXT NOT NULL,PRIMARY KEY(job_id,seq));
CREATE TRIGGER IF NOT EXISTS job_event_no_update BEFORE UPDATE ON job_events BEGIN SELECT RAISE(ABORT,'append-only job events'); END;
CREATE TRIGGER IF NOT EXISTS job_event_no_delete BEFORE DELETE ON job_events BEGIN SELECT RAISE(ABORT,'append-only job events'); END;

CREATE TABLE IF NOT EXISTS api_tokens(id TEXT PRIMARY KEY,token_hash TEXT NOT NULL UNIQUE,subject TEXT NOT NULL,actor TEXT NOT NULL,login_authority TEXT NOT NULL,name TEXT NOT NULL,roles TEXT NOT NULL,created TEXT NOT NULL,expires INTEGER NOT NULL,revoked TEXT NOT NULL,last_used INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS api_tokens_subject ON api_tokens(subject,created);
CREATE TRIGGER IF NOT EXISTS api_token_binding_immutable BEFORE UPDATE OF id,token_hash,subject,actor,login_authority,name,roles,created,expires ON api_tokens BEGIN SELECT RAISE(ABORT,'immutable API token'); END;
CREATE TRIGGER IF NOT EXISTS api_token_revocation_final BEFORE UPDATE OF revoked ON api_tokens WHEN OLD.revoked<>'' BEGIN SELECT RAISE(ABORT,'revoked API token'); END;
`

// brokerColumns are the version 6 additions: the host-signed seal key record a
// target publishes, a secret's injection rules and envelope context, and the
// host's receipt for it. None of them holds a secret value. addColumn makes
// each step idempotent, so a migration can be repeated safely.
var brokerColumns = []struct{ table, column, decl string }{
	{"targets", "seal_key", "TEXT NOT NULL DEFAULT ''"},
	{"secrets", "injection", "TEXT NOT NULL DEFAULT ''"},
	{"secrets", "envelope", "TEXT NOT NULL DEFAULT ''"},
	{"secrets", "receipt", "TEXT NOT NULL DEFAULT ''"},
}

// brokerTriggers keep the version 6 columns as immutable as the rest of the
// secret binding: injection rules and the envelope context never change, a
// receipt is recorded once, and a seal key record is JSON.
const brokerTriggers = `
DROP TRIGGER IF EXISTS secret_binding_immutable;
CREATE TRIGGER secret_binding_immutable BEFORE UPDATE OF id,name,target_id,upstreams,header,fingerprint,allowed_profiles,allowed_launchers,created,created_by,injection,envelope ON secrets BEGIN SELECT RAISE(ABORT,'immutable secret metadata'); END;
CREATE TRIGGER IF NOT EXISTS secret_receipt_once BEFORE UPDATE OF receipt ON secrets WHEN OLD.receipt<>'' AND NEW.receipt<>OLD.receipt BEGIN SELECT RAISE(ABORT,'immutable secret receipt'); END;
CREATE TRIGGER IF NOT EXISTS target_seal_key_json BEFORE UPDATE OF seal_key ON targets WHEN NEW.seal_key<>'' AND json_valid(NEW.seal_key)=0 BEGIN SELECT RAISE(ABORT,'invalid seal key record'); END;
`

// retirementColumns are the version 7 additions. targets.retiring is the time
// an administrator started retiring a target whose host still holds secrets:
// the target stays able to poll (state active) only to collect secret-delete
// jobs and is shown as "retiring". secrets.removal is "unconfirmed" for a
// secret whose host never confirmed the removal before the target was
// retired with force; the value may remain on that host.
var retirementColumns = []struct{ table, column, decl string }{
	{"targets", "retiring", "TEXT NOT NULL DEFAULT ''"},
	{"secrets", "removal", "TEXT NOT NULL DEFAULT ''"},
}

// migration is one forward-only schema step after version 7: columns added
// idempotently (addColumn) and statements that are idempotent themselves
// (CREATE ... IF NOT EXISTS, DROP ... IF EXISTS before a re-create).
type migration struct {
	version    int
	columns    []struct{ table, column, decl string }
	statements string
	// after runs once the statements have, in the same transaction.
	after func(tx *sql.Tx) error
}

// laterMigrations run in order from the database's version to SchemaVersion.
var laterMigrations = []migration{
	// Version 8: the profile version an administrator approved for launches
	// without a second human. Automatic approval needs the launched version's
	// digest to equal approved_digest; the trigger keeps the pair naming a
	// real version of the same profile.
	{version: 8, columns: []struct{ table, column, decl string }{
		{"profiles", "approved_version_id", "TEXT NOT NULL DEFAULT ''"},
		{"profiles", "approved_digest", "TEXT NOT NULL DEFAULT ''"},
		{"profiles", "approved_by", "TEXT NOT NULL DEFAULT ''"},
		{"profiles", "approved_at", "TEXT NOT NULL DEFAULT ''"},
	}, statements: `
DROP TRIGGER IF EXISTS profile_approved_version_exists;
CREATE TRIGGER profile_approved_version_exists BEFORE UPDATE OF approved_version_id,approved_digest ON profiles WHEN NEW.approved_digest<>'' AND NOT EXISTS (SELECT 1 FROM profile_versions v WHERE v.id=NEW.approved_version_id AND v.profile_id=NEW.id AND v.digest=NEW.approved_digest) BEGIN SELECT RAISE(ABORT,'approved profile version must exist'); END;
DROP TRIGGER IF EXISTS profile_approved_pair;
CREATE TRIGGER profile_approved_pair BEFORE UPDATE OF approved_version_id,approved_digest,approved_by,approved_at ON profiles WHEN (NEW.approved_digest='') <> (NEW.approved_version_id='') OR (NEW.approved_digest<>'' AND (NEW.approved_by='' OR NEW.approved_at='')) BEGIN SELECT RAISE(ABORT,'an approved profile version names its digest, administrator and time'); END;`},
	// Version 9: the host folders a target's launches may mount or snapshot
	// (a JSON list of roots). The default, an empty list, allows none.
	{version: 9, columns: []struct{ table, column, decl string }{
		{"targets", "mount_roots", "TEXT NOT NULL DEFAULT '[]'"},
	}, statements: `
DROP TRIGGER IF EXISTS target_mount_roots_json;
CREATE TRIGGER target_mount_roots_json BEFORE UPDATE OF mount_roots ON targets WHEN json_valid(NEW.mount_roots)=0 OR json_type(NEW.mount_roots)<>'array' BEGIN SELECT RAISE(ABORT,'mount roots are a JSON list'); END;`},
	// Version 10: the broker /29 each launch with secrets holds on its target
	// (prov_broker_pool.go). A block is held by at most one launch of a
	// target until released; the launches created before this version are
	// recorded from their plans.
	{version: 10, statements: `
CREATE TABLE IF NOT EXISTS broker_allocations(launch_id TEXT PRIMARY KEY,target_id TEXT NOT NULL,block INTEGER NOT NULL CHECK(block BETWEEN 1 AND 8191),allocated TEXT NOT NULL,released TEXT NOT NULL DEFAULT '');
CREATE UNIQUE INDEX IF NOT EXISTS broker_allocations_held ON broker_allocations(target_id,block) WHERE released='';
CREATE INDEX IF NOT EXISTS broker_allocations_target ON broker_allocations(target_id,released);
DROP TRIGGER IF EXISTS broker_allocation_binding;
CREATE TRIGGER broker_allocation_binding BEFORE UPDATE OF launch_id,target_id,block,allocated ON broker_allocations BEGIN SELECT RAISE(ABORT,'immutable broker allocation'); END;
DROP TRIGGER IF EXISTS broker_allocation_release_once;
CREATE TRIGGER broker_allocation_release_once BEFORE UPDATE OF released ON broker_allocations WHEN OLD.released<>'' BEGIN SELECT RAISE(ABORT,'a broker allocation is released once'); END;`, after: backfillBrokerAllocations},
}
