// SPDX-License-Identifier: GPL-2.0-only
// Private file-open component. This object is not a qualified full policy engine.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define PATH_MAX_BYTES 4096
#define NAME_BYTES 256
#define FMODE_READ 1
#define FMODE_WRITE 2
#define FMODE_EXEC 32
#define O_TRUNC 512
#define ALLOW 1
#define DENY 2

struct dentry;
struct vfsmount;
struct path { struct vfsmount *mnt; struct dentry *dentry; } __attribute__((preserve_access_index));
struct file { struct path f_path; unsigned int f_mode; unsigned int f_flags; } __attribute__((preserve_access_index));
struct action { __u32 effect, rule; };
struct node { __u32 id; struct action sub_read, sub_write, exact_read, exact_write; };
struct state { __u64 generation, expires_ns; struct node root; __u32 padding; };
struct key { __u64 domain, generation; __u32 parent; char name[NAME_BYTES]; __u32 padding; };
struct walk {
    struct action read, write;
    __u32 name_length, finished, error;
};
struct scratch { struct key key; char path[PATH_MAX_BYTES]; struct walk walk; };
struct stats_value { __u64 decisions, lost; };
struct event {
    __u64 sequence, generation, domain, mono_ns;
    __u32 pid, uid, operation, allowed, read_rule, write_rule, path_length, reason;
    char path[160];
};
_Static_assert(sizeof(struct key) == 280, "key ABI");
_Static_assert(sizeof(struct node) == 36, "node ABI");
_Static_assert(sizeof(struct state) == 56, "state ABI");
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,1024); __type(key,__u64); __type(value,__u32); } owned SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,1024); __type(key,__u64); __type(value,struct state); } policies SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(map_flags,BPF_F_NO_PREALLOC); __uint(max_entries,65536); __type(key,struct key); __type(value,struct node); } nodes SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries,1); __type(key,__u32); __type(value,struct scratch); } scratch SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,1); __type(key,__u32); __type(value,struct stats_value); } stats SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_RINGBUF); __uint(max_entries,1<<20); } events SEC(".maps");

static __always_inline struct action exact_action(struct action sub, struct action exact)
{
    if (!exact.effect || sub.effect == DENY) return sub;
    return exact;
}
static long component(__u32 i, void *opaque)
{
    __u32 zero=0;
    struct scratch *s=bpf_map_lookup_elem(&scratch,&zero);
    if (!s) return 1;
    // Keep callback state in the per-CPU map. The verifier then checks one
    // bounded callback instead of tracking thousands of evolving stack states.
    // This hook cannot sleep, and its helpers do not reenter file_open.
    struct walk *walk=&s->walk;
    // bpf_loop invokes only [0, PATH_MAX_BYTES). Keep the register bound
    // explicit for the verifier before adding it to a map value pointer.
    i &= PATH_MAX_BYTES-1;
    if (i==0) return 0;
    char c=s->path[i];
    __u32 name_length=walk->name_length;
    if (c && c!='/') {
        if (name_length>=NAME_BYTES-1) { walk->error=1; return 1; }
        s->key.name[name_length]=c;
        walk->name_length=name_length+1;
        return 0;
    }
    if (!name_length || name_length>=NAME_BYTES) { walk->error=1; return 1; }
    s->key.name[name_length]=0;
    struct node *node=bpf_map_lookup_elem(&nodes,&s->key);
    if (!node) { walk->finished=1; return 1; }
    if (node->sub_read.effect) walk->read=node->sub_read;
    if (node->sub_write.effect) walk->write=node->sub_write;
    if (!c) {
        struct action read=exact_action(node->sub_read,node->exact_read);
        struct action write=exact_action(node->sub_write,node->exact_write);
        if (read.effect) walk->read=read;
        if (write.effect) walk->write=write;
        walk->finished=1; return 1;
    }
    s->key.parent=node->id;
    __builtin_memset(s->key.name,0,sizeof(s->key.name));
    walk->name_length=0;
    return 0;
}
static __always_inline int emit(__u64 domain, __u64 generation, __u32 operations,
                                int allowed, struct walk *walk, long length, int reason)
{
    __u32 zero=0;
    struct stats_value *s=bpf_map_lookup_elem(&stats,&zero);
    if (!s) return -1;
    __u64 sequence=__sync_fetch_and_add(&s->decisions,1)+1;
    struct event *e=bpf_ringbuf_reserve(&events,sizeof(*e),0);
    if (!e) { __sync_fetch_and_add(&s->lost,1); return allowed?0:-1; }
    __builtin_memset(e,0,sizeof(*e));
    e->sequence=sequence;e->generation=generation;e->domain=domain;e->mono_ns=bpf_ktime_get_ns();
    e->pid=bpf_get_current_pid_tgid()>>32;e->uid=bpf_get_current_uid_gid();
    e->operation=operations;e->allowed=allowed;e->path_length=length>0?length:0;e->reason=reason;
    if (walk) {
        e->read_rule=walk->read.rule;e->write_rule=walk->write.rule;
        struct scratch *path=bpf_map_lookup_elem(&scratch,&zero);
        if (path) bpf_probe_read_kernel_str(e->path,sizeof(e->path),path->path);
    }
    bpf_ringbuf_submit(e,0);
    return allowed?0:-1;
}

SEC("lsm/file_open")
int BPF_PROG(file_open_rules,struct file *file,int ret)
{
    if (ret) return ret;
    __u64 domain=bpf_get_current_ancestor_cgroup_id(1);
    if (!bpf_map_lookup_elem(&owned,&domain)) return 0;
    __u32 modes=BPF_CORE_READ(file,f_mode),flags=BPF_CORE_READ(file,f_flags);
    __u32 operations=(modes&FMODE_READ?1:0)|((modes&FMODE_WRITE)||(flags&O_TRUNC)?2:0)|(modes&FMODE_EXEC?4:0);
    // Read permission never authorizes execution in this private component.
    if (operations&4) return emit(domain,0,operations,0,0,0,5);
    struct state *policy=bpf_map_lookup_elem(&policies,&domain);
    if (!policy || !policy->generation) return emit(domain,0,operations,0,0,0,1);
    __u64 generation=policy->generation;
    if (bpf_ktime_get_ns()>=policy->expires_ns) return emit(domain,generation,operations,0,0,0,2);
    __u32 zero=0;
    struct scratch *s=bpf_map_lookup_elem(&scratch,&zero);
    if (!s) return -1;
    s->key.domain=domain;s->key.generation=generation;s->key.parent=0;s->key.padding=0;
    __builtin_memset(s->key.name,0,sizeof(s->key.name));
    long length=bpf_d_path(&file->f_path,s->path,sizeof(s->path));
    if (length<=1 || length>PATH_MAX_BYTES || s->path[0]!='/') return emit(domain,generation,operations,0,0,0,3);
    __builtin_memset(&s->walk,0,sizeof(s->walk));
    s->walk.read=policy->root.sub_read;s->walk.write=policy->root.sub_write;
    if (length==2) {
        s->walk.read=exact_action(policy->root.sub_read,policy->root.exact_read);
        s->walk.write=exact_action(policy->root.sub_write,policy->root.exact_write);
        s->walk.finished=1;
    } else if (bpf_loop(PATH_MAX_BYTES,component,0,0)<0) s->walk.error=1;
    int allow=operations && s->walk.finished && !s->walk.error &&
        (!(operations&1)||s->walk.read.effect==ALLOW) && (!(operations&2)||s->walk.write.effect==ALLOW);
    return emit(domain,generation,operations,allow,&s->walk,length,s->walk.error?4:0);
}

SEC("cgroup/connect4") int file_component_connect4(struct bpf_sock_addr *ctx) { return 0; }
SEC("cgroup/connect6") int file_component_connect6(struct bpf_sock_addr *ctx) { return 0; }
char LICENSE[] SEC("license")="GPL";
