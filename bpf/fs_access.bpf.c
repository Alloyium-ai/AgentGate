// SPDX-License-Identifier: GPL-2.0-only
// Private file/program component. Mutation and runtime qualification stay separate.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define PATH_BYTES 4096
#define NAME_BYTES 256
#define OPERATIONS 14
#define READ 0
#define WRITE 1
#define MMAP 9
#define RECEIVE 10
#define EXECUTE 11
#define MAP_EXECUTE 12
#define MPROTECT 13
#define ALLOW 1
#define DENY 2
#define ANONYMOUS_DELEGATION (1ULL<<63)
#define ANONYMOUS_FS_MAGIC 0x09041934UL
struct dentry;struct vfsmount;
struct super_block {unsigned long s_magic;} __attribute__((preserve_access_index));
struct inode {__u64 i_ino;unsigned short i_mode;struct super_block *i_sb;} __attribute__((preserve_access_index));
struct path {struct vfsmount *mnt;struct dentry *dentry;} __attribute__((preserve_access_index));
struct file {struct inode *f_inode;struct path f_path;unsigned int f_mode,f_flags;} __attribute__((preserve_access_index));
struct linux_binprm {struct file *file;} __attribute__((preserve_access_index));
struct task_struct {__u64 start_boottime;} __attribute__((preserve_access_index));
struct vm_area_struct {struct file *vm_file;} __attribute__((preserve_access_index));
struct action {__u32 effect,rule;};
struct node {__u32 id;struct action sub_read,sub_write,exact_read,exact_write;};
struct state {__u64 generation,expires_ns;struct node roots[OPERATIONS];__u64 memory,pipes,socket_generation;};
struct key {__u64 domain,generation;__u32 parent;char name[NAME_BYTES];__u32 operation;};
struct walk {struct action result;__u32 name_length,finished,error;};
struct scratch {struct key key;char path[PATH_BYTES];struct walk walk;__u64 busy;};
struct file_key {__u64 domain,file;};
struct bootstrap_key {__u64 domain;__u32 pid,padding;};
struct bootstrap_binding {__u64 generation,expires_ns,start_ticks,pipe_ino;};
struct file_cookie {__u64 sequence,creator;};
struct file_grant {__u64 cookie,generation;char path[PATH_BYTES];};
struct counters {__u64 decisions,lost;};
struct event {__u64 sequence,generation,domain,mono_ns;__u32 pid,uid,operation,allowed,rule,reason;char path[160];};
_Static_assert(sizeof(struct state)==544,"file policy ABI");
_Static_assert(sizeof(struct key)==280,"path node ABI");
struct {__uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,1024);__type(key,__u64);__type(value,__u32);} owned SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,1024);__type(key,__u64);__type(value,struct state);} policies SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_HASH);__uint(map_flags,BPF_F_NO_PREALLOC);__uint(max_entries,65536);__type(key,struct key);__type(value,struct node);} nodes SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_PERCPU_ARRAY);__uint(max_entries,1);__type(key,__u32);__type(value,struct scratch);} scratch SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,1);__type(key,__u32);__type(value,struct counters);} stats SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_RINGBUF);__uint(max_entries,1<<20);} events SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,65536);__type(key,__u64);__type(value,struct file_cookie);} file_cookies SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,1);__type(key,__u32);__type(value,__u64);} cookie_sequence SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_HASH);__uint(map_flags,BPF_F_NO_PREALLOC);__uint(max_entries,16384);__type(key,struct file_key);__type(value,struct file_grant);} file_grants SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,16384);__type(key,__u64);__type(value,struct file_key);} file_grant_keys SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_HASH);__uint(max_entries,1024);__type(key,struct bootstrap_key);__type(value,struct bootstrap_binding);} bootstrap SEC(".maps");
const struct file_grant empty_grant={};

static __always_inline struct action direct(struct node *node)
{
    if (!node->exact_read.effect || node->sub_read.effect==DENY) return node->sub_read;
    return node->exact_read;
}
static long component(__u32 i,void *unused)
{
    __u32 zero=0;struct scratch *s=bpf_map_lookup_elem(&scratch,&zero);if(!s)return 1;
    i&=PATH_BYTES-1;if(!i)return 0;
    char c=s->path[i];__u32 length=s->walk.name_length;
    if(c && c!='/') {if(length>=NAME_BYTES-1){s->walk.error=1;return 1;}s->key.name[length]=c;s->walk.name_length=length+1;return 0;}
    if(!length || length>=NAME_BYTES){s->walk.error=1;return 1;}
    s->key.name[length]=0;struct node *node=bpf_map_lookup_elem(&nodes,&s->key);
    if(!node){s->walk.finished=1;return 1;}
    if(node->sub_read.effect)s->walk.result=node->sub_read;
    if(!c){struct action action=direct(node);if(action.effect)s->walk.result=action;s->walk.finished=1;return 1;}
    s->key.parent=node->id;__builtin_memset(s->key.name,0,NAME_BYTES);s->walk.name_length=0;return 0;
}
static __always_inline int emit(__u64 domain,__u64 generation,__u32 operation,int allow,__u32 rule,int reason,struct scratch *s)
{
    __u32 zero=0;struct counters *count=bpf_map_lookup_elem(&stats,&zero);if(!count)return -1;
    __u64 sequence=__sync_fetch_and_add(&count->decisions,1)+1;
    struct event *e=bpf_ringbuf_reserve(&events,sizeof(*e),0);
    if(!e){__sync_fetch_and_add(&count->lost,1);return -1;}
    __builtin_memset(e,0,sizeof(*e));e->sequence=sequence;e->generation=generation;e->domain=domain;e->mono_ns=bpf_ktime_get_ns();
    e->pid=bpf_get_current_pid_tgid()>>32;e->uid=bpf_get_current_uid_gid();e->operation=operation;e->allowed=!!allow;e->rule=rule;e->reason=reason;
    if(s)bpf_probe_read_kernel_str(e->path,sizeof(e->path),s->path);
    bpf_ringbuf_submit(e,0);return allow?0:-1;
}
static __always_inline int evaluate(struct scratch *s,__u64 domain,struct state *p,__u32 operation)
{
    if(operation>=OPERATIONS)return -1;
    __builtin_memset(&s->walk,0,sizeof(s->walk));s->key.domain=domain;s->key.generation=p->generation;s->key.parent=0;s->key.operation=operation;
    __builtin_memset(s->key.name,0,NAME_BYTES);s->walk.result=p->roots[operation].sub_read;
    if(s->path[0]!='/' || !s->path[1]){if(s->path[0]=='/'){s->walk.result=direct(&p->roots[operation]);s->walk.finished=1;}}
    else if(bpf_loop(PATH_BYTES,component,0,0)<0)s->walk.error=1;
    int allow=s->walk.finished && !s->walk.error && s->walk.result.effect==ALLOW && bpf_ktime_get_ns()<p->expires_ns;
    return emit(domain,p->generation,operation,allow,s->walk.result.rule,s->walk.error?4:0,s);
}
static __always_inline int check_path(struct path *path,__u32 operation)
{
    __u64 domain=bpf_get_current_ancestor_cgroup_id(1);if(!bpf_map_lookup_elem(&owned,&domain))return 0;
    struct state *p=bpf_map_lookup_elem(&policies,&domain);
    if(!p || !p->generation)return emit(domain,0,operation,0,0,1,0);
    if(bpf_ktime_get_ns()>=p->expires_ns)return emit(domain,p->generation,operation,0,0,2,0);
    __u32 zero=0;struct scratch *s=bpf_map_lookup_elem(&scratch,&zero);if(!s)return -1;
    if(__sync_val_compare_and_swap(&s->busy,0,1))return emit(domain,p->generation,operation,0,0,10,0);
    long length=bpf_d_path(path,s->path,PATH_BYTES);
    int result=length<=1 || length>PATH_BYTES?emit(domain,p->generation,operation,0,0,3,0):evaluate(s,domain,p,operation);
    __sync_lock_test_and_set(&s->busy,0);return result;
}
static __always_inline __u64 cookie(struct file *file,int replace)
{
    __u64 key=(__u64)file;struct file_cookie *old=bpf_map_lookup_elem(&file_cookies,&key);
    if(old && !replace)return old->sequence;
    __u32 zero=0;__u64 *sequence=bpf_map_lookup_elem(&cookie_sequence,&zero);if(!sequence)return 0;
    __u64 value=__sync_fetch_and_add(sequence,1)+1;if(!value)return 0;
    struct file_cookie fresh={value,bpf_get_current_ancestor_cgroup_id(1)};
    if(bpf_map_update_elem(&file_cookies,&key,&fresh,replace?BPF_ANY:BPF_NOEXIST)) {old=bpf_map_lookup_elem(&file_cookies,&key);return old?old->sequence:0;}
    return value;
}
static __always_inline int cache(struct file *file)
{
    __u64 domain=bpf_get_current_ancestor_cgroup_id(1);if(!bpf_map_lookup_elem(&owned,&domain))return 0;
    struct state *p=bpf_map_lookup_elem(&policies,&domain);if(!p || !p->generation || bpf_ktime_get_ns()>=p->expires_ns)return -1;
    __u64 identity=cookie(file,0);if(!identity)return -1;
    struct file_key key={domain,(__u64)file};__u64 ptr=(__u64)file;
    if(bpf_map_update_elem(&file_grant_keys,&ptr,&key,BPF_ANY))return -1;
    if(bpf_map_update_elem(&file_grants,&key,&empty_grant,BPF_ANY))return -1;
    struct file_grant *grant=bpf_map_lookup_elem(&file_grants,&key);if(!grant)return -1;
    grant->cookie=identity;grant->generation=p->generation;
    if(bpf_d_path(&file->f_path,grant->path,PATH_BYTES)<=1){bpf_map_delete_elem(&file_grants,&key);return -1;}
    return 0;
}
static __always_inline int cached(struct file *file,__u32 operation)
{
    __u64 domain=bpf_get_current_ancestor_cgroup_id(1);if(!bpf_map_lookup_elem(&owned,&domain))return 0;
    struct state *p=bpf_map_lookup_elem(&policies,&domain);
    if(!p || !p->generation || bpf_ktime_get_ns()>=p->expires_ns)return emit(domain,p?p->generation:0,operation,0,0,1,0);
    struct file_key key={domain,(__u64)file};__u64 ptr=(__u64)file;
    struct file_grant *grant=bpf_map_lookup_elem(&file_grants,&key);struct file_cookie *identity=bpf_map_lookup_elem(&file_cookies,&ptr);
    if(!grant || !identity || grant->cookie!=identity->sequence || grant->generation!=p->generation)return emit(domain,p->generation,operation,0,0,6,0);
    __u32 zero=0;struct scratch *s=bpf_map_lookup_elem(&scratch,&zero);if(!s)return -1;
    if(__sync_val_compare_and_swap(&s->busy,0,1))return emit(domain,p->generation,operation,0,0,10,0);
    int result=bpf_probe_read_kernel_str(s->path,PATH_BYTES,grant->path)<=1?-1:evaluate(s,domain,p,operation);
    __sync_lock_test_and_set(&s->busy,0);return result;
}
SEC("lsm/file_alloc_security") int BPF_PROG(fs_alloc,struct file *file,int ret)
{if(ret)return ret;__u64 domain=bpf_get_current_ancestor_cgroup_id(1);if(cookie(file,1))return 0;return bpf_map_lookup_elem(&owned,&domain)?-1:0;}
SEC("lsm/file_free_security") int BPF_PROG(fs_free,struct file *file)
{struct bootstrap_key held={bpf_get_current_ancestor_cgroup_id(1),bpf_get_current_pid_tgid()>>32,0};struct bootstrap_binding *role=bpf_map_lookup_elem(&bootstrap,&held);if(role && BPF_CORE_READ(file,f_inode,i_sb,s_magic)==0x50495045UL && BPF_CORE_READ(file,f_inode,i_ino)==role->pipe_ino)bpf_map_delete_elem(&bootstrap,&held);__u64 key=(__u64)file;struct file_key *grant=bpf_map_lookup_elem(&file_grant_keys,&key);if(grant)bpf_map_delete_elem(&file_grants,grant);bpf_map_delete_elem(&file_grant_keys,&key);bpf_map_delete_elem(&file_cookies,&key);return 0;}
SEC("lsm/file_open") int BPF_PROG(fs_open,struct file *file,int ret)
{
    if(ret)return ret;__u32 mode=BPF_CORE_READ(file,f_mode),flags=BPF_CORE_READ(file,f_flags);
    if(!(mode&(1|2|32))){__u64 domain=bpf_get_current_ancestor_cgroup_id(1);return bpf_map_lookup_elem(&owned,&domain)?emit(domain,0,READ,0,0,8,0):0;}
    if((mode&1) && check_path(&file->f_path,READ))return -1;
    if(((mode&2)||(flags&512)) && check_path(&file->f_path,WRITE))return -1;
    if((mode&32) && check_path(&file->f_path,EXECUTE))return -1;
    return cache(file);
}
static __always_inline int bootstrap_read(struct file *file,__u64 domain,struct state *policy,int mask)
{
    struct bootstrap_key key={domain,bpf_get_current_pid_tgid()>>32,0};
    struct bootstrap_binding *binding=bpf_map_lookup_elem(&bootstrap,&key);if(!binding)return 1;
    if(mask!=4 || !policy || !policy->generation || policy->generation!=binding->generation || bpf_ktime_get_ns()>=binding->expires_ns || bpf_ktime_get_ns()>=policy->expires_ns)return 1;
    if(BPF_CORE_READ(file,f_inode,i_sb,s_magic)!=0x50495045UL || BPF_CORE_READ(file,f_inode,i_ino)!=binding->pipe_ino)return 1;
    struct task_struct *task=(void *)bpf_get_current_task_btf();
    if(BPF_CORE_READ(task,start_boottime)/10000000ULL!=binding->start_ticks)return 1;
    return emit(domain,policy->generation,18,1,0,14,0);
}
static __always_inline int special_file(struct file *file,int mask)
{
    __u64 domain=bpf_get_current_ancestor_cgroup_id(1);if(!bpf_map_lookup_elem(&owned,&domain))return 0;
    struct state *p=bpf_map_lookup_elem(&policies,&domain);
    int held=bootstrap_read(file,domain,p,mask);if(held!=1)return held;
    if(!p || !p->generation || bpf_ktime_get_ns()>=p->expires_ns)return emit(domain,p?p->generation:0,READ,0,0,1,0);
    unsigned short mode=BPF_CORE_READ(file,f_inode,i_mode);
    if((mode&0170000)==0140000)return p->socket_generation==p->generation?0:emit(domain,p->generation,READ,0,0,12,0);
    if(BPF_CORE_READ(file,f_inode,i_sb,s_magic)==ANONYMOUS_FS_MAGIC && (p->pipes&ANONYMOUS_DELEGATION))return 0;
    if(BPF_CORE_READ(file,f_inode,i_sb,s_magic)!=0x50495045UL)return 1;
    __u64 ptr=(__u64)file;struct file_cookie *identity=bpf_map_lookup_elem(&file_cookies,&ptr);
    __u64 required=1|((mask&4)?2:0)|((mask&2)?4:0);
    int valid=identity && identity->creator==domain && !(mask&~6) && (mask&6) && (p->pipes&required)==required;
    return emit(domain,p->generation,(mask&4)?16:17,valid,0,valid?0:13,0);
}
SEC("lsm/file_permission") int BPF_PROG(fs_use,struct file *file,int mask,int ret)
{if(ret)return ret;int special=special_file(file,mask);if(special!=1)return special;if((mask&~(4|2|8)) || !(mask&(4|2|8))){__u64 domain=bpf_get_current_ancestor_cgroup_id(1);return bpf_map_lookup_elem(&owned,&domain)?emit(domain,0,READ,0,0,8,0):0;}if((mask&4) && cached(file,READ))return -1;if((mask&(2|8)) && cached(file,WRITE))return -1;return 0;}
SEC("lsm/file_receive") int BPF_PROG(fs_receive,struct file *file,int ret)
{if(ret)return ret;__u64 domain=bpf_get_current_ancestor_cgroup_id(1);if(bpf_map_lookup_elem(&owned,&domain) && BPF_CORE_READ(file,f_inode,i_sb,s_magic)==ANONYMOUS_FS_MAGIC){struct state *p=bpf_map_lookup_elem(&policies,&domain);if(p && p->generation && bpf_ktime_get_ns()<p->expires_ns && (p->pipes&ANONYMOUS_DELEGATION))return 0;}if(check_path(&file->f_path,RECEIVE))return -1;__u32 mode=BPF_CORE_READ(file,f_mode);if((mode&1)&&check_path(&file->f_path,READ))return -1;if((mode&2)&&check_path(&file->f_path,WRITE))return -1;return cache(file);}
SEC("lsm/bprm_check_security") int BPF_PROG(fs_exec,struct linux_binprm *bprm,int ret)
{if(ret)return ret;struct bootstrap_key key={bpf_get_current_ancestor_cgroup_id(1),bpf_get_current_pid_tgid()>>32,0};bpf_map_delete_elem(&bootstrap,&key);struct file *file=bprm->file;return file?check_path(&file->f_path,EXECUTE):-1;}
SEC("lsm/inode_getattr") int BPF_PROG(fs_getattr,struct path *path,int ret)
{return ret?ret:check_path(path,READ);}
static __always_inline int anonymous_memory(unsigned long prot,int protect)
{
    __u64 domain=bpf_get_current_ancestor_cgroup_id(1);if(!bpf_map_lookup_elem(&owned,&domain))return 0;
    struct state *p=bpf_map_lookup_elem(&policies,&domain);
    __u32 operation=protect?15:14;
    if(!p || !p->generation || bpf_ktime_get_ns()>=p->expires_ns)return emit(domain,p?p->generation:0,operation,0,0,1,0);
    __u64 required=(protect?16:8)|(prot&7);
    int allow=!(prot&~7UL) && (p->memory&required)==required;
    return emit(domain,p->generation,operation,allow,0,allow?0:11,0);
}
// MAP_ANONYMOUS is a trusted hook scalar. Older BTF omits file nullable metadata.
// Classify this flag before any file path access; a NULL test alone can disappear.
SEC("lsm/mmap_file") int BPF_PROG(fs_mmap,struct file *file,unsigned long reqprot,unsigned long prot,unsigned long flags,int ret)
{if(ret)return ret;if(flags&0x20UL)return anonymous_memory(prot,0);if(!file)return -1;if(check_path(&file->f_path,MMAP))return -1;if((prot&1)&&check_path(&file->f_path,READ))return -1;if((prot&2)&&(flags&1)&&check_path(&file->f_path,WRITE))return -1;if((prot&4)&&check_path(&file->f_path,MAP_EXECUTE))return -1;return 0;}
SEC("lsm/file_mprotect") int BPF_PROG(fs_mprotect,struct vm_area_struct *vma,unsigned long reqprot,unsigned long prot,int ret)
{if(ret)return ret;struct file *file=BPF_CORE_READ(vma,vm_file);if(!file)return anonymous_memory(prot,1);if(cached(file,MPROTECT))return -1;if((prot&1)&&cached(file,READ))return -1;if((prot&2)&&cached(file,WRITE))return -1;if((prot&4)&&cached(file,MAP_EXECUTE))return -1;return 0;}

// Namespace mutations stay denied until the trusted anchor implementation qualifies.
// This preserves the approved cached path during the access component witness.
static __always_inline int mutation(__u32 operation)
{__u64 domain=bpf_get_current_ancestor_cgroup_id(1);if(!bpf_map_lookup_elem(&owned,&domain))return 0;return emit(domain,0,operation,0,0,7,0);}
struct inode;struct mnt_idmap;struct iattr;
SEC("lsm/inode_create") int BPF_PROG(fs_create,struct inode *dir,struct dentry *dentry,unsigned short mode,int ret){return ret?ret:mutation(2);}
SEC("lsm/inode_mkdir") int BPF_PROG(fs_mkdir,struct inode *dir,struct dentry *dentry,unsigned short mode,int ret){return ret?ret:mutation(3);}
SEC("lsm/inode_mknod") int BPF_PROG(fs_mknod,struct inode *dir,struct dentry *dentry,unsigned short mode,unsigned int dev,int ret){return ret?ret:mutation(2);}
SEC("lsm/path_unlink") int BPF_PROG(fs_unlink,struct path *dir,struct dentry *dentry,int ret){return ret?ret:mutation(4);}
SEC("lsm/path_rmdir") int BPF_PROG(fs_rmdir,struct path *dir,struct dentry *dentry,int ret){return ret?ret:mutation(4);}
SEC("lsm/path_rename") int BPF_PROG(fs_rename,struct path *old_dir,struct dentry *old_dentry,struct path *new_dir,struct dentry *new_dentry,unsigned int flags,int ret){return ret?ret:mutation(5);}
SEC("lsm/path_link") int BPF_PROG(fs_link,struct dentry *old_dentry,struct path *new_dir,struct dentry *new_dentry,int ret){return ret?ret:mutation(6);}
SEC("lsm/path_symlink") int BPF_PROG(fs_symlink,struct path *dir,struct dentry *dentry,const char *target,int ret){return ret?ret:mutation(7);}
SEC("lsm/path_chmod") int BPF_PROG(fs_chmod,struct path *path,unsigned short mode,int ret){return ret?ret:mutation(8);}
SEC("lsm/path_chown") int BPF_PROG(fs_chown,struct path *path,unsigned int uid,unsigned int gid,int ret){return ret?ret:mutation(8);}
SEC("lsm/path_truncate") int BPF_PROG(fs_truncate,struct path *path,int ret){return ret?ret:check_path(path,WRITE);}
SEC("lsm/file_ioctl") int BPF_PROG(fs_ioctl,struct file *file,unsigned int cmd,unsigned long arg,int ret){return ret?ret:mutation(8);}
char LICENSE[] SEC("license")="GPL";
