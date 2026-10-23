// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// Fixed qualification actor. Initial exec is a fixture; agent exec never occurs.
#define _GNU_SOURCE
#include <asm/prctl.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/filter.h>
#include <linux/futex.h>
#include <linux/seccomp.h>
#include <linux/random.h>
#include <linux/stat.h>
#include <netinet/in.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

struct record { uint32_t id, error; int64_t result; uint32_t pid, reserved; };
static uint32_t actor_pid;
static int output_fd;
static volatile sig_atomic_t authorized_parent;
static volatile sig_atomic_t release_pid;
static volatile sig_atomic_t release_uid;
static volatile sig_atomic_t release_code;
static volatile sig_atomic_t bootstrap_ready;
static volatile sig_atomic_t phase;
static struct sock_filter final[4096];
static uint16_t final_length;
static const char *input_path,*output_path;
static long heap_base;
static uint8_t pilot_family;
static uint16_t pilot_port;
static uint8_t pilot_address[16];
static int clear_child_tid;
static int futex_word;
static struct robust_list_head robust_head;
static int candidate_body(void);
static int emit(uint32_t id, long value, int error);

// These bounded calls produce real post-install syscall and file events. A
// denied call contributes no positive case; the verifier checks raw results.
static void probe_one_byte(const char *path)
{
    int fd=(int)syscall(SYS_openat,AT_FDCWD,path,O_RDONLY|O_CLOEXEC,0);
    if(fd>=0){unsigned char value;syscall(SYS_read,fd,&value,1);syscall(SYS_close,fd);}
}

static void probe_safe_syscalls(int input_fd)
{
    char cwd[256],random_bytes[8],entries[512];
    struct utsname system_name;
    struct rlimit limit;
    struct stat file_stat;
    struct statx extended_stat;
    cpu_set_t affinity;
    struct pollfd polled={.fd=input_fd,.events=POLLIN};
    struct timespec zero={0};
    struct epoll_event event={.events=EPOLLIN,.data.fd=input_fd},ready;
    syscall(SYS_getpid);syscall(SYS_gettid);
    syscall(SYS_getuid);syscall(SYS_geteuid);
    syscall(SYS_getgid);syscall(SYS_getegid);
    syscall(SYS_getcwd,cwd,sizeof(cwd));
    syscall(SYS_uname,&system_name);
    syscall(SYS_getrandom,random_bytes,sizeof(random_bytes),GRND_NONBLOCK);
    syscall(SYS_getrlimit,RLIMIT_NOFILE,&limit);
    syscall(SYS_prlimit64,0,RLIMIT_NOFILE,0,&limit);
    syscall(SYS_sched_getaffinity,0,sizeof(affinity),&affinity);
    unsigned long fs_base=0;
    syscall(SYS_arch_prctl,ARCH_GET_FS,&fs_base);
    struct sigaction old_action;
    sigset_t old_mask;
    syscall(SYS_rt_sigaction,SIGUSR1,0,&old_action,sizeof(unsigned long));
    syscall(SYS_rt_sigprocmask,SIG_SETMASK,0,&old_mask,sizeof(unsigned long));
    syscall(SYS_fcntl,input_fd,F_GETFD);
    syscall(SYS_newfstatat,AT_FDCWD,"/usr/bin/dash",&file_stat,0);
    syscall(SYS_statx,AT_FDCWD,"/usr/bin/dash",0,STATX_BASIC_STATS,&extended_stat);
    syscall(SYS_poll,&polled,1,0);
    syscall(SYS_ppoll,&polled,1,&zero,0,0);
    int epfd=(int)syscall(SYS_epoll_create1,EPOLL_CLOEXEC);
    if(epfd>=0){
        syscall(SYS_epoll_ctl,epfd,EPOLL_CTL_ADD,input_fd,&event);
        syscall(SYS_epoll_wait,epfd,&ready,1,0);
        syscall(SYS_close,epfd);
    }
    int directory=(int)syscall(SYS_openat,AT_FDCWD,"/usr",O_RDONLY|O_DIRECTORY|O_CLOEXEC,0);
    if(directory>=0){syscall(SYS_getdents64,directory,entries,sizeof(entries));syscall(SYS_close,directory);}
    probe_one_byte("/usr/bin/dash");
    probe_one_byte("/etc/passwd");
    void *memory=(void*)syscall(SYS_mmap,0,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(memory!=MAP_FAILED){
        *(volatile unsigned char*)memory=0x5a;
        long moved=syscall(SYS_mremap,memory,4096,8192,MREMAP_MAYMOVE);
        size_t length=4096;
        if(moved>=0){memory=(void*)moved;length=8192;}
        syscall(SYS_madvise,memory,length,MADV_DONTNEED);
        syscall(SYS_mprotect,memory,length,PROT_READ);
        syscall(SYS_munmap,memory,length);
    }
    int duplicate=(int)syscall(SYS_dup2,input_fd,100);
    if(duplicate==100)syscall(SYS_close,duplicate);
    syscall(SYS_futex,&futex_word,FUTEX_WAKE_PRIVATE,1,0,0,0);
    syscall(SYS_set_tid_address,&clear_child_tid);
    robust_head.list.next=&robust_head.list;
    syscall(SYS_set_robust_list,&robust_head,sizeof(robust_head));
}

static void probe_signed_taskboard_endpoint(void)
{
    if(pilot_family!=4 && pilot_family!=6)return;
    int family=pilot_family==4?AF_INET:AF_INET6;
    int fd=(int)syscall(SYS_socket,family,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,IPPROTO_TCP);
    if(fd<0)return;
    int enabled=1,connection_error=0;
    socklen_t length=sizeof(connection_error);
    syscall(SYS_setsockopt,fd,SOL_SOCKET,SO_KEEPALIVE,&enabled,sizeof(enabled));
    syscall(SYS_getsockopt,fd,SOL_SOCKET,SO_ERROR,&connection_error,&length);
    struct sockaddr_storage local={0};
    socklen_t local_length=sizeof(local);
    syscall(SYS_getsockname,fd,&local,&local_length);
    struct sockaddr_storage destination={0};
    socklen_t destination_length;
    if(pilot_family==4){
        struct sockaddr_in *v4=(struct sockaddr_in*)&destination;
        v4->sin_family=AF_INET;v4->sin_port=htons(pilot_port);
        memcpy(&v4->sin_addr,pilot_address,4);
        destination_length=sizeof(*v4);
    }else{
        struct sockaddr_in6 *v6=(struct sockaddr_in6*)&destination;
        v6->sin6_family=AF_INET6;v6->sin6_port=htons(pilot_port);
        memcpy(&v6->sin6_addr,pilot_address,16);
        destination_length=sizeof(*v6);
    }
    errno=0;
    long connected=syscall(SYS_connect,fd,&destination,destination_length);
    if(connected==0 || (connected<0 && errno==EINPROGRESS)){
        struct pollfd waiting={.fd=fd,.events=POLLOUT};
        if(syscall(SYS_poll,&waiting,1,250)>0){
            length=sizeof(connection_error);
            if(syscall(SYS_getsockopt,fd,SOL_SOCKET,SO_ERROR,&connection_error,&length)==0 && connection_error==0){
                struct sockaddr_storage peer={0};
                socklen_t peer_length=sizeof(peer);
                syscall(SYS_getpeername,fd,&peer,&peer_length);
                static const char request[]="HEAD /api/health HTTP/1.0\r\nHost: taskboard\r\n\r\n";
                syscall(SYS_sendto,fd,request,sizeof(request)-1,MSG_DONTWAIT,0,0);
                waiting.events=POLLIN;
                if(syscall(SYS_poll,&waiting,1,250)>0){
                    char response;
                    syscall(SYS_recvfrom,fd,&response,1,MSG_DONTWAIT,0,0);
                }
                syscall(SYS_shutdown,fd,SHUT_RDWR);
            }
        }
    }
    syscall(SYS_close,fd);
}

// Both destinations are this VM's own loopback. A failed guard cannot turn
// this fixed denial stimulus into a scan of a LAN peer.
static int probe_owned_loopback(int family, uint32_t socket_id, uint32_t connect_id)
{
    errno=0;
    int fd=(int)syscall(SYS_socket,family,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,IPPROTO_TCP);
    int socket_error=errno;
    if(emit(socket_id,fd,socket_error))return -1;
    if(fd<0)return emit(connect_id,-2,0);
    struct sockaddr_storage destination={0};
    socklen_t length;
    if(family==AF_INET){
        struct sockaddr_in *v4=(struct sockaddr_in*)&destination;
        v4->sin_family=AF_INET;v4->sin_port=htons(pilot_port);
        v4->sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        length=sizeof(*v4);
    }else{
        struct sockaddr_in6 *v6=(struct sockaddr_in6*)&destination;
        v6->sin6_family=AF_INET6;v6->sin6_port=htons(pilot_port);
        v6->sin6_addr.s6_addr[15]=1;
        length=sizeof(*v6);
    }
    errno=0;
    long connected=syscall(SYS_connect,fd,&destination,length);
    int connect_error=errno;
    int recorded=emit(connect_id,connected,connect_error);
    syscall(SYS_close,fd);
    return recorded;
}

static __attribute__((noreturn)) void finish(int status)
{
    syscall(SYS_exit_group,status);__builtin_unreachable();
}

static void resume_handler(int signal,siginfo_t *info,void *context)
{
    (void)context;
    if(signal!=SIGCONT || !info || (info->si_code!=SI_USER && info->si_code!=SI_TKILL) || info->si_pid!=authorized_parent || info->si_uid!=0)return;
    release_pid=info->si_pid;release_uid=info->si_uid;release_code=info->si_code;
    if(!bootstrap_ready)finish(12);
    if(phase==0){phase=1;finish(candidate_body());}
    if(phase==2){errno=0;long expired=syscall(SYS_brk,heap_base+4096);finish(expired==-1 && errno==EPERM?0:11);}
    finish(12);
}

static int read_all(int fd, void *data, size_t length)
{
    char *p=data;
    while(length){long n=syscall(SYS_read,fd,p,length);if(n<=0)return -1;p+=n;length-=n;}
    return 0;
}
static int emit(uint32_t id, long value, int error)
{
    struct record r={id,(uint32_t)error,value,actor_pid,0};
    return syscall(SYS_write,output_fd,&r,sizeof(r))==(long)sizeof(r)?0:-1;
}
static long monotonic_ms(void)
{
    struct timespec value;
    if(syscall(SYS_clock_gettime,CLOCK_MONOTONIC,&value))return -1;
    return value.tv_sec*1000+value.tv_nsec/1000000;
}
static int barrier(int fd, unsigned char wanted)
{
    long deadline=monotonic_ms()+3000;
    for(;;){
        unsigned char value=0;
        if(syscall(SYS_lseek,fd,0,SEEK_SET)<0 || syscall(SYS_read,fd,&value,1)!=1)return -1;
        if(value==wanted)return 0;
        long now=monotonic_ms();if(now<0 || now>=deadline)return -1;
        for(volatile unsigned i=0;i<500000;i++){}
    }
}
#define RECORD(id,call) do { errno=0;long value=(long)(call);int error=errno;if(emit(id,value,error))return 40; } while(0)
#define CREATE_RECORD(id,call) do { errno=0;long value=(long)(call);int error=errno;if(value==0)finish(90);if(emit(id,value,error))return 40; } while(0)

static int send_listener(int listener,const char *binding)
{
    char data[72];memcpy(data,"AGQSN001",8);memcpy(data+8,binding,64);
    struct iovec vector={.iov_base=data,.iov_len=sizeof(data)};
    union { struct cmsghdr alignment; char bytes[CMSG_SPACE(sizeof(int))]; } control={0};
    struct msghdr message={.msg_iov=&vector,.msg_iovlen=1,.msg_control=control.bytes,.msg_controllen=sizeof(control.bytes)};
    struct cmsghdr *header=CMSG_FIRSTHDR(&message);
    header->cmsg_level=SOL_SOCKET;header->cmsg_type=SCM_RIGHTS;header->cmsg_len=CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header),&listener,sizeof(listener));
    return syscall(SYS_sendmsg,4,&message,0)==(long)sizeof(data)?0:-1;
}

static int pilot_stream_pair(const char *input,const char *output)
{
    const char *prefix="/run/agentgate/streams/.qualification-";
    size_t length=strlen(prefix);
    if(strncmp(input,prefix,length) || strncmp(output,prefix,length))return 0;
    const char *input_leaf=strchr(input+length,'/');
    const char *output_leaf=strchr(output+length,'/');
    if(!input_leaf || !output_leaf || input_leaf==input+length ||
       (size_t)(input_leaf-input)>=length+25 ||
       output_leaf-output!=input_leaf-input ||
       strncmp(input,output,(size_t)(input_leaf-input)) ||
       strcmp(input_leaf,"/input") || strcmp(output_leaf,"/output"))return 0;
    for(const char *p=input+length;p<input_leaf;p++)
        if(!((*p>='a'&&*p<='z')||(*p>='A'&&*p<='Z')||(*p>='0'&&*p<='9')))return 0;
    return 1;
}

int main(int argc,char **argv)
{
    if(argc!=4 || !((!strncmp(argv[1],"/var/lib/",9) && !strncmp(argv[2],"/var/lib/",9)) ||
                    pilot_stream_pair(argv[1],argv[2])))return 2;
    if(strcmp(argv[3],"candidate-listener"))return 2;
    char marker[64]={0};int fd=open("/etc/alloyium-disposable-vm",O_RDONLY);
    if(fd<0)return 3;
    ssize_t count=read(fd,marker,63);close(fd);
    if(count<11 || strncmp(marker,"kernel-poc-",11))return 3;
    struct sock_filter setup[4096];uint16_t setup_length=0;
    input_path=argv[1];output_path=argv[2];
    char header[8],binding[64];
    if(read_all(3,header,sizeof(header)) || memcmp(header,"AGQCF003",8) || read_all(3,&setup_length,sizeof(setup_length)) || read_all(3,&final_length,sizeof(final_length)) || read_all(3,binding,sizeof(binding)) || read_all(3,&pilot_family,sizeof(pilot_family)) || read_all(3,&pilot_port,sizeof(pilot_port)) || read_all(3,pilot_address,sizeof(pilot_address)))return 4;
    if((pilot_family!=0 && pilot_family!=4 && pilot_family!=6) || (pilot_family==0 && pilot_port!=0) || (pilot_family!=0 && pilot_port==0))return 4;
    if(!setup_length || setup_length>4096 || !final_length || final_length>4096 || read_all(3,setup,setup_length*sizeof(setup[0])) || read_all(3,final,final_length*sizeof(final[0])))return 4;
    for(unsigned i=0;i<sizeof(binding);i++)if(!((binding[i]>='0'&&binding[i]<='9')||(binding[i]>='a'&&binding[i]<='f')))return 4;
    close(3);actor_pid=(uint32_t)getpid();pid_t parent=getppid();authorized_parent=parent;
    struct sigaction action={0};action.sa_sigaction=resume_handler;action.sa_flags=SA_SIGINFO|SA_NODEFER;
    sigset_t blocked;sigfillset(&blocked);sigdelset(&blocked,SIGCONT);
    if(sigaction(SIGCONT,&action,0) || sigprocmask(SIG_BLOCK,&blocked,0))return 5;
    if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0) || setgroups(0,0) || setgid(65534) || setuid(65534))return 5;
    if(prctl(PR_SET_PDEATHSIG,SIGKILL,0,0,0) || getppid()!=parent)return 5;
    close(0);close(1);close(2);
    struct sock_fprog program={.len=setup_length,.filter=setup};
    int listener=(int)syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,SECCOMP_FILTER_FLAG_NEW_LISTENER,&program);
    if(listener<0 || send_listener(listener,binding))return 6;
    syscall(SYS_close,listener);syscall(SYS_close,4);
    // The parent verifies zero descriptors before it stops this trusted worker.
    bootstrap_ready=1;
    for(;;){for(volatile unsigned i=0;i<500000;i++){}}
}

static int candidate_body(void)
{
    // The authenticated handler enters this body and never returns through sigreturn.
    struct sock_fprog program={.len=final_length,.filter=final};
    if(syscall(SYS_seccomp,SECCOMP_SET_MODE_FILTER,0,&program))return 7;
    int input_fd=(int)syscall(SYS_openat,AT_FDCWD,input_path,O_RDONLY,0);
    output_fd=(int)syscall(SYS_openat,AT_FDCWD,output_path,O_WRONLY,0);
    if(input_fd<0 || output_fd<0)return 8;
    if(emit(1,0,0) || emit(2,release_pid,0) || emit(3,release_uid,0) || emit(4,release_code,0) || barrier(input_fd,1))return 9;
    probe_safe_syscalls(input_fd);
    probe_signed_taskboard_endpoint();
    if(pilot_family && (probe_owned_loopback(AF_INET,60,61) ||
                        probe_owned_loopback(AF_INET6,62,63)))return 41;
    RECORD(10,syscall(SYS_getppid));
    RECORD(11,syscall(0x3fffffff));
    RECORD(12,syscall(SYS_clone3,0,0));
    errno=0;long child=syscall(SYS_clone,SIGCHLD,0,0,0,0);int child_error=errno;
    if(child==0)finish(90);
    if(emit(50,child,child_error))return 40;
    if(child>0){
        int status=0;
        RECORD(53,syscall(SYS_wait4,child,&status,0,0));
        if(emit(54,status,0))return 40;
    }
    CREATE_RECORD(51,syscall(SYS_fork));
    CREATE_RECORD(52,syscall(SYS_vfork));
    int descriptors[2]={-1,-1};
    RECORD(13,syscall(SYS_pipe,descriptors));
    RECORD(14,syscall(SYS_pipe2,descriptors,0));
    if(descriptors[0]>=0 && descriptors[1]>=0){
        struct stat read_stat={0},write_stat={0};
        unsigned char sent=0x5a,received=0;
        RECORD(28,syscall(SYS_fstat,descriptors[0],&read_stat));
        if(emit(29,read_stat.st_mode,0) || emit(30,read_stat.st_ino,0))return 40;
        RECORD(31,syscall(SYS_fstat,descriptors[1],&write_stat));
        if(emit(32,write_stat.st_mode,0) || emit(33,write_stat.st_ino,0))return 40;
        RECORD(34,syscall(SYS_write,descriptors[1],&sent,1));
        RECORD(35,syscall(SYS_read,descriptors[0],&received,1));
        if(emit(36,received,0))return 40;
        struct iovec vector={.iov_base=&sent,.iov_len=1};
        syscall(SYS_writev,descriptors[1],&vector,1);
        vector.iov_base=&received;
        syscall(SYS_readv,descriptors[0],&vector,1);
        int epfd=(int)syscall(SYS_epoll_create1,EPOLL_CLOEXEC);
        if(epfd>=0){
            struct epoll_event event={.events=EPOLLIN,.data.fd=descriptors[0]},ready;
            syscall(SYS_epoll_ctl,epfd,EPOLL_CTL_ADD,descriptors[0],&event);
            syscall(SYS_epoll_wait,epfd,&ready,1,0);
            syscall(SYS_close,epfd);
        }
        syscall(SYS_close,descriptors[0]);syscall(SYS_close,descriptors[1]);
    }
    RECORD(15,syscall(SYS_eventfd,0));
    RECORD(16,syscall(SYS_eventfd2,0,0));
    RECORD(17,syscall(SYS_kill,actor_pid,0));
    RECORD(18,syscall(SYS_tkill,actor_pid,0));
    RECORD(19,syscall(SYS_tgkill,actor_pid,actor_pid,0));
    RECORD(20,syscall(SYS_setuid,0));
    RECORD(21,syscall(SYS_prctl,PR_SET_NO_NEW_PRIVS,0,0,0,0));
    RECORD(22,syscall(SYS_mmap,0,4096,PROT_READ|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS,-1,0));
    RECORD(23,syscall(SYS_mmap,0,4096,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS,-1,0));
    errno=0;long heap=syscall(SYS_brk,0);int heap_error=errno;
    if(emit(24,heap,heap_error))return 40;
    if(heap>0){
        errno=0;long grown=syscall(SYS_brk,heap+4096);int grow_error=errno;
        if(emit(25,grown,grow_error))return 40;
        if(grown==heap+4096){*(volatile unsigned char*)heap=1;if(emit(27,*(volatile unsigned char*)heap,0))return 40;}
        RECORD(26,syscall(SYS_brk,heap));
    }
    if(emit(99,0,0) || barrier(input_fd,2))return 10;
    if(heap>0){
        heap_base=heap;phase=2;
        if(emit(100,0,0))return 10;
        // The parent holds this exact worker until the candidate maps expire.
        for(;;){for(volatile unsigned i=0;i<500000;i++){}}
    }
    return 0;
}
