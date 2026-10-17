// SPDX-License-Identifier: GPL-2.0-only
// Process ownership restrictions grant no syscall or resource right.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#define EPERM 1
struct kernfs_node {__u64 id;} __attribute__((preserve_access_index));
struct cgroup {int level;struct kernfs_node *kn;struct cgroup *ancestors[];} __attribute__((preserve_access_index));
struct css_set {struct cgroup *dfl_cgrp;} __attribute__((preserve_access_index));
struct task_struct {struct css_set *cgroups;int tgid;} __attribute__((preserve_access_index));
struct kernel_siginfo;struct cred;
struct process_state {__u64 generation,expires_ns,signals;};
struct process_stats {__u64 decisions,lost;};
struct process_event {
 __u64 sequence,domain,target_domain,cgroup,generation,mono_ns;
 __u32 pid,uid,hook;int signal;__u32 mode,allowed,reason,target_pid;
};
_Static_assert(sizeof(struct process_state)==24,"process policy ABI");
_Static_assert(sizeof(struct process_event)==80,"process event ABI");
struct {__uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,1024);__type(key,__u64);__type(value,__u32);} proc_managed SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,1024);__type(key,__u64);__type(value,struct process_state);} proc_policies SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,1);__type(key,__u32);__type(value,struct process_stats);} proc_stats SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_RINGBUF);__uint(max_entries,1<<20);} proc_events SEC(".maps");
static __always_inline __u64 task_domain(struct task_struct *task)
{
 if(!task)return 0;
 struct cgroup *group=BPF_CORE_READ(task,cgroups,dfl_cgrp);
 if(!group || BPF_CORE_READ(group,level)<1)return 0;
 struct cgroup *root=0;if(bpf_core_read(&root,sizeof(root),&group->ancestors[1]) || !root)return 0;
 return BPF_CORE_READ(root,kn,id);
}
static __always_inline int emit(__u64 domain,__u64 target,struct task_struct *task,
 struct process_state *policy,__u32 hook,int signal,__u32 mode,__u32 reason)
{
 __u32 zero=0;struct process_stats *stats=bpf_map_lookup_elem(&proc_stats,&zero);
 if(!stats)return -EPERM;
 {
  __u64 sequence=__sync_fetch_and_add(&stats->decisions,1)+1;
  struct process_event *event=bpf_ringbuf_reserve(&proc_events,sizeof(*event),0);
  if(!event){__sync_fetch_and_add(&stats->lost,1);return -EPERM;}
  __builtin_memset(event,0,sizeof(*event));event->sequence=sequence;event->domain=domain;event->target_domain=target;
  event->cgroup=bpf_get_current_cgroup_id();event->generation=policy?policy->generation:0;event->mono_ns=bpf_ktime_get_ns();
  event->pid=bpf_get_current_pid_tgid()>>32;event->uid=bpf_get_current_uid_gid();event->hook=hook;event->signal=signal;
  event->mode=mode;event->allowed=!reason;event->reason=reason;event->target_pid=task?BPF_CORE_READ(task,tgid):0;
  bpf_ringbuf_submit(event,0);
 }
 return reason?-EPERM:0;
}
static __always_inline int check(struct task_struct *task,__u32 hook,int signal,__u32 mode,int ret)
{
 __u64 domain=bpf_get_current_ancestor_cgroup_id(1);
 __u32 *managed=bpf_map_lookup_elem(&proc_managed,&domain);if(!managed)return ret;
 struct process_state *policy=bpf_map_lookup_elem(&proc_policies,&domain);__u64 target=task_domain(task);__u32 reason=0;
 if(ret)reason=11;
 else if(*managed!=1)reason=9;
 else if(!policy || !policy->generation)reason=1;
 else if(bpf_ktime_get_ns()>=policy->expires_ns)reason=2;
 else if(hook==3)reason=7;
 else if(!target)reason=10;
 else {
  __u32 *owner=bpf_map_lookup_elem(&proc_managed,&target);
  if(!owner || *owner!=1)reason=6;
  else if(target!=domain)reason=5;
  else if(hook==1){if(signal<1 || signal>64)reason=3;else if(!(policy->signals&(1ULL<<((__u32)signal-1))))reason=4;}
  else if(mode&2)reason=7;
  else if(!(mode&1) || (mode&~(__u32)(1|4|8|16)))reason=8;
 }
 int result=emit(domain,target,task,policy,hook,signal,mode,reason);return ret?ret:result;
}
SEC("lsm/task_kill") int BPF_PROG(process_signal,struct task_struct *target,struct kernel_siginfo *info,int signal,const struct cred *cred,int ret)
{return check(target,1,signal,0,ret);}
SEC("lsm/ptrace_access_check") int BPF_PROG(process_ptrace,struct task_struct *target,unsigned int mode,int ret)
{return check(target,2,0,mode,ret);}
SEC("lsm/ptrace_traceme") int BPF_PROG(process_traceme,struct task_struct *parent,int ret)
{return check(parent,3,0,0,ret);}
char LICENSE[] SEC("license")="GPL";
