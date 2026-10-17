/* SPDX-License-Identifier: Apache-2.0 */
// Copyright (c) 2026 Dan Metcalf
/* Trusted, bounded process-custody witness. It executes no agent program. */
#include <sys/prctl.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
int main(int argc, char **argv) {
  if (argc != 2 || strlen(argv[1]) != 32) return 2;
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return 3;
  if (write(4, argv[1], 32) != 32 || write(4, "\n", 1) != 1) return 4;
  char token[32]; size_t count = 0;
  while (count < sizeof(token)) {
    ssize_t got = read(3, token + count, sizeof(token) - count);
    if (got <= 0) return 5;
    count += (size_t)got;
  }
  if (memcmp(token, argv[1], sizeof(token)) != 0) return 6;
  for (int i = 0; i < 2; i++) {
    pid_t child = fork();
    if (child < 0) return 7;
    if (child == 0) for (;;) pause();
  }
  if (write(4, "descendants-ready\n", 18) != 18) return 8;
  for (;;) pause();
}
