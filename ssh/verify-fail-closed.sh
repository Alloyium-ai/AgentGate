#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
set -eu
mkdir -p /etc/agentgate/authorized_keys
ssh-keygen -q -t ed25519 -N '' -f /etc/agentgate/ssh_host_ed25519_key
ssh-keygen -q -t ed25519 -N '' -f /etc/agentgate/test_client_key
printf '[127.0.0.1]:2222 %s\n' "$(cat /etc/agentgate/ssh_host_ed25519_key.pub)" > /etc/agentgate/known_hosts
cp /etc/agentgate/test_client_key.pub /etc/agentgate/authorized_keys/agentgate-ssh
chmod 0755 /etc/agentgate /etc/agentgate/authorized_keys
chmod 0644 /etc/agentgate/authorized_keys/agentgate-ssh
/usr/sbin/sshd -D -e -f /etc/ssh/sshd_config > /run/sshd/test.log 2>&1 &
server=$!
trap 'kill "$server" 2>/dev/null || true' EXIT
sleep 1
set +e
ssh -n -T -o BatchMode=yes -o ConnectTimeout=3 -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/etc/agentgate/known_hosts -i /etc/agentgate/test_client_key -p 2222 agentgate-ssh@127.0.0.1 'touch /var/empty/UNSAFE' > /run/sshd/client.out 2> /run/sshd/client.err
status=$?
set -e
if test "$status" -eq 0 || test -e /var/empty/UNSAFE || ! grep -q '"error"' /run/sshd/client.err || ! grep -q 'Starting session: forced-command' /run/sshd/test.log; then
  printf 'status=%s marker=%s\n' "$status" "$(test -e /var/empty/UNSAFE && echo yes || echo no)"
  sed -n '1,15p' /run/sshd/client.err
  sed -n '1,15p' /run/sshd/test.log
  exit 1
fi
echo ssh-transport-fail-closed
