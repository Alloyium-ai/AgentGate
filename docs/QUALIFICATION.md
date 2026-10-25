# Experimental source-preview status

This document describes a source preview. It does not attest a production workload, kernel target or complete confinement policy.
The public identity and exact file hashes appear in `SOURCE-MANIFEST.json`.

## Current build checks

The exported context builds without the private monorepo or fleet adapter.
Its Docker targets run Go race tests, schema unit tests, a browser workspace test with owned mock responses, TypeScript checks and npm audit.
The BPF target compiles the selected inspection object. Build results and kernel behavior evidence have separate meanings.
Some kernel tests require a marked disposable VM or explicit protected fixtures. Read the actual test output for skips and prerequisites.

Normal full-policy admission remains unavailable when any required capability lacks complete, fresh behavior evidence.
A successful build, available hook or signed report alone does not establish that evidence.
This preview provides no real-agent or model-turn qualification.

## Historical scope

Engineering notes dated14October2026 reported local login, role, policy, restart and restore checks.
They also reported a selected existing-file write and a new IPv4 TCP connection on a dedicated Linux6.8.0-142 VM.
Those notes do not provide a current public source-to-artifact attestation. They do not qualify this snapshot.
The private raw evidence and infrastructure details are excluded from this distribution.

## Kernel assumptions to re-verify on each new kernel

The SSH and launch POC's filesystem component (`bpf/fs_access.bpf.c`) depends on kernel internals that are not a stable
interface. Its target is Linux 6.8.0-142; the object compiles and its CO-RE field names resolve against a 6.18 kernel's
BTF, but no BPF LSM program has been loaded or exercised on any kernel. Before trusting a run on a kernel, check each item
against that kernel's source and BTF, then run `poc/ssh-diagnostic/verify-kernel.sh`:

1. **`path_mknod` caller set.** `security_path_mknod` is called only from `may_o_create()` (open with `O_CREAT` of a missing
   name, `mode` = `S_IFREG|perm`, `dev` = 0, `dir` = `&nd->path`), `do_mknodat()` and `unix_bind_bsd()` (plus `init_mknod()`
   during boot). A new caller needs its own review.
2. **`current->nameidata` timing.** It is published (`set_nameidata()` in `do_filp_open()`/`do_file_open_root()`) while
   `may_o_create()` runs, and restored (`restore_nameidata()` at the end of `filename_create()`'s walk) before `do_mknodat()` and
   `unix_bind_bsd()` call the hook.
3. **Open intent.** `open_last_lookups()` ORs `op->intent` into `nd->flags` before `lookup_open()`; `build_open_flags()` sets
   `LOOKUP_OPEN` (0x0100) and, for `O_CREAT`, `LOOKUP_CREATE` (0x0200); `filename_create()` never sets `LOOKUP_OPEN` on its walk.
4. **Directory argument.** `lookup_open()` passes `&nd->path` to `may_o_create()`.
5. **Syscall numbers.** `task_pt_regs(current)->orig_ax` is the x86-64 syscall in progress: `open` 2, `creat` 85, `openat` 257,
   `openat2` 437 (`mknod` 133, `mknodat` 259); `bpf_task_pt_regs` is available to BPF LSM programs.
6. **`FMODE_CREATED`** is 0x100000 and `lookup_open()` sets it after `->create()` and before `security_file_open()`.
7. **Sleepable LSM hook set.** `bpf_d_path` is called only from hooks in the kernel's sleepable set (`file_open`,
   `file_receive`, `bprm_check_security`, `inode_getattr`, `mmap_file`, `path_mkdir`, `path_unlink`, `path_rmdir`,
   `path_rename`, `path_symlink`, `path_chmod`, `path_chown`, `path_truncate`); `internal/fsrules` tests enforce the source side.
8. **CO-RE fields** (`task_struct.nameidata`, `nameidata.path`, `nameidata.flags`, `pt_regs.orig_ax`, and the `file`, `inode`,
   `dentry`, `super_block` fields the object declares) exist in the kernel's BTF with compatible types.
9. **Pipe identity.** Anonymous pipes live on pipefs (`PIPEFS_MAGIC` 0x50495045) and keep one inode number for their lifetime;
   the gateway's recorded stdio pipes are matched by that number and the `file_permission` mask bits `MAY_READ` (4) and
   `MAY_WRITE` (2).

Items 2 to 4 fail closed when they change: creating a new file with `open(O_CREAT)` is denied, and `mknod(2)` stays denied
because item 5 is the syscall ABI. The kit's `allow-create` and `deny-mknod-regular` probes observe both sides.

## Remaining product work

Full filesystem, executable, descriptor, network, socket, process, memory and lifecycle contracts need exact target behavior evidence.
The full-policy report producer refuses incomplete coverage. The limited inspection path has the narrower limits stated in the README.
Existing descriptors and established connections lack immediate revocation in that limited path.
Host and node custody remain trusted. Audit signatures do not replace those trust assumptions.

Independent code, security and privacy review, exact dependency notices and provenance review precede a source release.
Production and image releases require separate supported-platform and workload acceptance.
The authorized first-party Community migration is complete: user-space source uses Apache-2.0.
BPF retains GPL-2.0-only, documentation retains CC-BY-4.0, and third-party components retain their supplier terms.
