// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

// SchemaVersion is the database user_version this build writes.
const SchemaVersion = 6

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
