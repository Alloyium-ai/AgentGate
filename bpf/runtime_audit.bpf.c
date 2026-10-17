// SPDX-License-Identifier: GPL-2.0-only
// Audit only: tracepoints record outcomes and cannot deny or undo an action.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct task_struct {int tgid,exit_code;__u64 start_boottime;struct task_struct *real_parent;} __attribute__((preserve_access_index));
struct audit_binding {__u64 generation,expires_ns;};
struct audit_stats {__u64 records,lost;};
struct audit_event {
 __u64 sequence,domain,cgroup,generation,mono_ns,task_start_boot_ns;
 __s64 syscall_id,result;
 __u32 tgid,tid,uid,type;
 __s32 exit_code;
 __u32 binding_state,parent_tgid,flags;
 __u64 parent_start_boot_ns;
 __s64 original_id;
 __u64 entry_mono_ns;
 __u32 version,origin_flags;
};
_Static_assert(sizeof(struct audit_event)==128,"syscalls128.v2 event ABI");
struct audit_origin {__u64 domain,generation,task_start_boot_ns,mono_ns;__s64 id;};
struct sys_enter_context {__u64 common;__s64 id;__u64 args[6];};
struct sys_exit_context {__u64 common;__s64 id,ret;};
struct {__uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,64);__type(key,__u64);__type(value,__u32);} audit_managed SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,64);__type(key,__u64);__type(value,struct audit_binding);} audit_bindings SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,1);__type(key,__u32);__type(value,struct audit_stats);} audit_stats SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_RINGBUF);__uint(max_entries,1<<20);} audit_events SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,8192);__type(key,__u64);__type(value,struct audit_origin);} audit_origin SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int audit_sys_enter(struct sys_enter_context *context)
{
 __u64 key=bpf_get_current_pid_tgid();
 bpf_map_delete_elem(&audit_origin,&key);
 __u64 domain=bpf_get_current_ancestor_cgroup_id(1);
 __u32 *managed=bpf_map_lookup_elem(&audit_managed,&domain);
 if(!managed||*managed!=1)return 0;
 struct audit_binding *binding=bpf_map_lookup_elem(&audit_bindings,&domain);
 if(!binding)return 0;
 struct task_struct *task=(struct task_struct *)bpf_get_current_task_btf();
 struct audit_origin origin={.domain=domain,.generation=binding->generation,
  .task_start_boot_ns=BPF_CORE_READ(task,start_boottime),.mono_ns=bpf_ktime_get_ns(),.id=context->id};
 bpf_map_update_elem(&audit_origin,&key,&origin,BPF_ANY);
 return 0;
}
static __always_inline int record(__u32 type,__s64 id,__s64 result)
{
 __u64 domain=bpf_get_current_ancestor_cgroup_id(1);
 __u32 *managed=bpf_map_lookup_elem(&audit_managed,&domain);
 if(!managed)return 0;
 __u32 zero=0;
 struct audit_stats *stats=bpf_map_lookup_elem(&audit_stats,&zero);
 if(!stats)return 0;
 __u64 sequence=__sync_fetch_and_add(&stats->records,1)+1;
 struct audit_event *event=bpf_ringbuf_reserve(&audit_events,sizeof(*event),0);
 if(!event){__sync_fetch_and_add(&stats->lost,1);return 0;}
 __builtin_memset(event,0,sizeof(*event));
 event->sequence=sequence;event->domain=domain;event->cgroup=bpf_get_current_cgroup_id();event->mono_ns=bpf_ktime_get_ns();
 struct audit_binding *binding=bpf_map_lookup_elem(&audit_bindings,&domain);
 if(binding)event->generation=binding->generation;
 if(*managed!=1)event->binding_state=3;
 else if(!binding)event->binding_state=1;
 else if(!binding->generation||!binding->expires_ns)event->binding_state=3;
 else if(event->mono_ns>=binding->expires_ns)event->binding_state=2;
 __u64 identity=bpf_get_current_pid_tgid();event->tgid=identity>>32;event->tid=(__u32)identity;event->uid=(__u32)bpf_get_current_uid_gid();
 struct task_struct *task=(struct task_struct *)bpf_get_current_task_btf();
 event->task_start_boot_ns=BPF_CORE_READ(task,start_boottime);
 struct task_struct *parent=BPF_CORE_READ(task,real_parent);
 if(parent){event->parent_tgid=BPF_CORE_READ(parent,tgid);event->parent_start_boot_ns=BPF_CORE_READ(parent,start_boottime);}
 event->type=type;event->syscall_id=id;event->result=result;
 event->version=2;event->original_id=-1;
 if(type==1&&id>=0){event->original_id=id;event->origin_flags=1;}
 if(type==1&&id<0)event->flags=1;
 if(type==1&&id==-1){
  struct audit_origin *origin=bpf_map_lookup_elem(&audit_origin,&identity);
  if(origin&&origin->domain==domain&&origin->generation==event->generation&&
   origin->task_start_boot_ns==event->task_start_boot_ns&&origin->id>=0&&
   origin->mono_ns&&origin->mono_ns<=event->mono_ns){
   event->original_id=origin->id;event->entry_mono_ns=origin->mono_ns;event->origin_flags=2;
  }
 }
 if(type==2)event->exit_code=BPF_CORE_READ(task,exit_code);
 bpf_ringbuf_submit(event,0);return 0;
}
SEC("tracepoint/raw_syscalls/sys_exit")
int audit_sys_exit(struct sys_exit_context *context){int result=record(1,context->id,context->ret);__u64 key=bpf_get_current_pid_tgid();bpf_map_delete_elem(&audit_origin,&key);return result;}
SEC("tracepoint/sched/sched_process_exit")
int audit_task_exit(void *context){int result=record(2,-1,0);__u64 key=bpf_get_current_pid_tgid();bpf_map_delete_elem(&audit_origin,&key);return result;}
char LICENSE[] SEC("license")="GPL";
