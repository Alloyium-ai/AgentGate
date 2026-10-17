// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// Fixed qualification actor. Initial exec is a fixture; agent exec never occurs.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
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
static int candidate_body(void);

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

int main(int argc,char **argv)
{
    if(argc!=4 || strncmp(argv[1],"/var/lib/",9) || strncmp(argv[2],"/var/lib/",9))return 2;
    if(strcmp(argv[3],"candidate-listener"))return 2;
    char marker[64]={0};int fd=open("/etc/alloyium-disposable-vm",O_RDONLY);
    if(fd<0)return 3;
    ssize_t count=read(fd,marker,63);close(fd);
    if(count<11 || strncmp(marker,"kernel-poc-",11))return 3;
    struct sock_filter setup[4096];uint16_t setup_length=0;
    input_path=argv[1];output_path=argv[2];
    char header[8],binding[64];
    if(read_all(3,header,sizeof(header)) || memcmp(header,"AGQCF002",8) || read_all(3,&setup_length,sizeof(setup_length)) || read_all(3,&final_length,sizeof(final_length)) || read_all(3,binding,sizeof(binding)))return 4;
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
    RECORD(10,syscall(SYS_getppid));
    RECORD(11,syscall(0x3fffffff));
    RECORD(12,syscall(SYS_clone3,0,0));
    CREATE_RECORD(50,syscall(SYS_clone,SIGCHLD,0,0,0,0));
    CREATE_RECORD(51,syscall(SYS_fork));
    CREATE_RECORD(52,syscall(SYS_vfork));
    int descriptors[2]={-1,-1};
    RECORD(13,syscall(SYS_pipe,descriptors));
    RECORD(14,syscall(SYS_pipe2,descriptors,0));
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
