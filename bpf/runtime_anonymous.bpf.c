// SPDX-License-Identifier: GPL-2.0-only
// Explicit anonymous object rights. The file component owns object cookies.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define ANON_INODE_MAGIC 0x09041934UL
#define EVENTFD2_NR 290
#define EVENTFD_NR 284
#define GUARD (1ULL << 63)
#define CREATE 8ULL
#define READ 16ULL
#define WRITE 32ULL

struct super_block { unsigned long s_magic; } __attribute__((preserve_access_index));
struct inode { struct super_block *i_sb; } __attribute__((preserve_access_index));
struct qstr { __u32 len; const unsigned char *name; } __attribute__((preserve_access_index));
struct dentry { struct qstr d_name; } __attribute__((preserve_access_index));
struct vfsmount;
struct path { struct vfsmount *mnt; struct dentry *dentry; } __attribute__((preserve_access_index));
struct file { struct inode *f_inode; struct path f_path; } __attribute__((preserve_access_index));
struct task_struct;
struct pt_regs { unsigned long orig_ax; } __attribute__((preserve_access_index));
struct action { __u32 effect,rule; };
struct node { __u32 id; struct action sub_read,sub_write,exact_read,exact_write; };
struct state { __u64 generation,expires_ns; struct node roots[14]; __u64 memory,pipes,socket_generation; };
struct file_cookie { __u64 sequence,creator; };
struct grant { __u64 cookie,domain,generation; };
struct counters { __u64 decisions,lost; };
struct event { __u64 sequence,generation,domain,mono_ns; __u32 pid,uid,operation,allowed,rule,reason; char path[160]; };
_Static_assert(sizeof(struct state)==544,"shared file policy ABI");
_Static_assert(sizeof(struct event)==216,"shared file event ABI");
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,1024); __type(key,__u64); __type(value,__u32); } owned SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,1024); __type(key,__u64); __type(value,struct state); } policies SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,65536); __type(key,__u64); __type(value,struct file_cookie); } file_cookies SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,1); __type(key,__u32); __type(value,struct counters); } stats SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_RINGBUF); __uint(max_entries,1<<20); } events SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,65536); __type(key,__u64); __type(value,struct grant); } anonymous_grants SEC(".maps");

static __always_inline int emit(__u64 domain,struct state *p,__u32 operation,int allow,__u32 reason)
{
    __u32 zero=0; struct counters *count=bpf_map_lookup_elem(&stats,&zero);
    if(!count)return -1;
    __u64 sequence=__sync_fetch_and_add(&count->decisions,1)+1;
    struct event *event=bpf_ringbuf_reserve(&events,sizeof(*event),0);
    if(!event){__sync_fetch_and_add(&count->lost,1);return -1;}
    __builtin_memset(event,0,sizeof(*event));
    event->sequence=sequence;event->generation=p?p->generation:0;event->domain=domain;
    event->mono_ns=bpf_ktime_get_ns();event->pid=bpf_get_current_pid_tgid()>>32;
    event->uid=bpf_get_current_uid_gid();event->operation=operation;event->allowed=!!allow;event->reason=reason;
    bpf_ringbuf_submit(event,0);return allow?0:-1;
}
static __always_inline int live(struct state *p)
{return p && p->generation && bpf_ktime_get_ns()<p->expires_ns;}

// file_alloc_security runs before f_inode exists. Only the target native
// eventfd2 syscall can receive an eventfd grant at this hook.
SEC("lsm/file_alloc_security") int BPF_PROG(anonymous_alloc,struct file *file,int ret)
{
    if(ret)return ret;
    __u64 key=(__u64)file;
    bpf_map_delete_elem(&anonymous_grants,&key);
    __u64 domain=bpf_get_current_ancestor_cgroup_id(1);
    if(!bpf_map_lookup_elem(&owned,&domain))return 0;
    struct state *p=bpf_map_lookup_elem(&policies,&domain);
    if(!live(p))return emit(domain,p,23,0,1);
    struct task_struct *task=(void *)bpf_get_current_task_btf();
    struct pt_regs *regs=(void *)bpf_task_pt_regs(task);
    unsigned long nr=BPF_CORE_READ(regs,orig_ax);
    if(nr!=EVENTFD2_NR && nr!=EVENTFD_NR)return 0;
    if(nr!=EVENTFD2_NR || (p->pipes&(GUARD|CREATE))!=(GUARD|CREATE))return emit(domain,p,19,0,16);
    // Allocation hooks can attach in either order. Bind the cookie only after
    // the completed object passes actual eventfd classification at first use.
    struct grant grant={0,domain,p->generation};
    if(bpf_map_update_elem(&anonymous_grants,&key,&grant,BPF_ANY))return emit(domain,p,19,0,17);
    return emit(domain,p,19,1,0);
}
static __always_inline int is_anonymous(struct file *file)
{return BPF_CORE_READ(file,f_inode,i_sb,s_magic)==ANON_INODE_MAGIC;}
static __always_inline int is_eventfd(struct file *file)
{
    if(BPF_CORE_READ(file,f_path.dentry,d_name.len)!=9)return 0;
    const unsigned char *name=BPF_CORE_READ(file,f_path.dentry,d_name.name);
    char label[10]={};
    if(bpf_probe_read_kernel_str(label,sizeof(label),name)!=10)return 0;
    return label[0]=='[' && label[1]=='e' && label[2]=='v' && label[3]=='e' &&
        label[4]=='n' && label[5]=='t' && label[6]=='f' && label[7]=='d' && label[8]==']' && !label[9];
}
SEC("lsm/file_permission") int BPF_PROG(anonymous_use,struct file *file,int mask,int ret)
{
    if(ret)return ret;
    __u64 domain=bpf_get_current_ancestor_cgroup_id(1);
    if(!bpf_map_lookup_elem(&owned,&domain) || !is_anonymous(file))return 0;
    struct state *p=bpf_map_lookup_elem(&policies,&domain);
    __u32 operation=(mask&4)?20:21;
    if(!is_eventfd(file))return emit(domain,p,22,0,15);
    if(!live(p))return emit(domain,p,operation,0,1);
    __u64 required=GUARD|CREATE|((mask&4)?READ:0)|((mask&2)?WRITE:0);
    if((mask&~6) || !(mask&6) || (p->pipes&required)!=required)return emit(domain,p,operation,0,16);
    __u64 key=(__u64)file;struct file_cookie *cookie=bpf_map_lookup_elem(&file_cookies,&key);
    struct grant *grant=bpf_map_lookup_elem(&anonymous_grants,&key);
    if(!cookie || !grant || !cookie->sequence || cookie->creator!=domain ||
        grant->domain!=domain || grant->generation!=p->generation)return emit(domain,p,operation,0,17);
    __u64 previous=__sync_val_compare_and_swap(&grant->cookie,0,cookie->sequence);
    if(previous && previous!=cookie->sequence)return emit(domain,p,operation,0,17);
    return emit(domain,p,operation,1,0);
}
SEC("lsm/file_receive") int BPF_PROG(anonymous_receive,struct file *file,int ret)
{
    if(ret)return ret;
    __u64 domain=bpf_get_current_ancestor_cgroup_id(1);
    if(!bpf_map_lookup_elem(&owned,&domain) || !is_anonymous(file))return 0;
    struct state *p=bpf_map_lookup_elem(&policies,&domain);
    return emit(domain,p,22,0,18);
}
SEC("lsm/file_free_security") int BPF_PROG(anonymous_free,struct file *file)
{__u64 key=(__u64)file;bpf_map_delete_elem(&anonymous_grants,&key);return 0;}
char LICENSE[] SEC("license")="GPL";
