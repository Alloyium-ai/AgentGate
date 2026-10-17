/* SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
 * Static amd64 lifecycle actor. No libc, network, file or credential access.
 * Build: cc -nostdlib -static -fno-stack-protector -fno-pie -no-pie
 *        -Werror -Wall -Wextra -Wl,-e,_start -o WORKER this-file.c
 */
typedef unsigned int u32;
typedef long i64;
typedef int i32;

struct record {
    u32 magic;
    u32 role;
    u32 pid;
    u32 ppid;
    i64 clone_result;
    u32 error;
    i32 gettid_result;
};
_Static_assert(sizeof(struct record) == 32, "the lifecycle wire record must be 32 bytes");

static i64 call6(i64 number, i64 a, i64 b, i64 c, i64 d, i64 e, i64 f)
{
    register i64 r10 __asm__("r10") = d;
    register i64 r8 __asm__("r8") = e;
    register i64 r9 __asm__("r9") = f;
    i64 result;
    __asm__ volatile("syscall" : "=a"(result)
                     : "a"(number), "D"(a), "S"(b), "d"(c),
                       "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return result;
}

__attribute__((noreturn)) static void finish(i64 code)
{
    call6(231, code, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}

static void emit(u32 role, i64 child)
{
    struct record out = {
        .magic = 0x41474c32,
        .role = role,
        .pid = (u32)call6(39, 0, 0, 0, 0, 0, 0),
        .ppid = (u32)call6(110, 0, 0, 0, 0, 0, 0),
        .clone_result = child,
        .error = child < 0 ? (u32)-child : 0,
        .gettid_result = (i32)call6(186, 0, 0, 0, 0, 0, 0)
    };
    if (call6(1, 1, (i64)&out, sizeof(out), 0, 0, 0) != (i64)sizeof(out)) {
        finish(74);
    }
}

static u32 wait_word;

__attribute__((noreturn)) static void hold(void)
{
    for (;;) {
        i64 result = call6(202, (i64)&wait_word, 128, 0, 0, 0, 0);
        if (result != 0 && result != -4) {
            finish(74);
        }
    }
}

__attribute__((used,noreturn)) void lifecycle_main(void)
{
    char command = 0;
    if (call6(0, 0, (i64)&command, 1, 0, 0, 0) != 1) {
        finish(64);
    }
    if (command == 'E') {
        emit(1, 0);
        finish(0);
    }
    if (command != 'T') {
        finish(64);
    }
    i64 child = call6(56, 17, 0, 0, 0, 0, 0);
    if (child != 0) {
        emit(1, child);
        if (child < 0) {
            finish(70);
        }
        hold();
    }
    i64 grandchild = call6(56, 17, 0, 0, 0, 0, 0);
    if (grandchild != 0) {
        emit(2, grandchild);
        if (grandchild < 0) {
            finish(70);
        }
        hold();
    }
    emit(3, 0);
    hold();
}

__asm__(".global _start\n_start:\nandq $-16,%rsp\ncall lifecycle_main\n");
