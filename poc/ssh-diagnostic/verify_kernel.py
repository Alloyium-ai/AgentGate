#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
"""Logic of the kernel verification kit (verify-kernel.sh).

The shell script runs the stages on a disposable BPF LSM VM; this module
builds the probe launch, judges each check against its expected outcome, and
writes the JSON verification report. It decides nothing about trust: the
service attaches the report to a target and decides whether to mark the
kernel verified. The host agent never sets kernel_verified itself.

Commands:
  job ID           print the probe launcher job (stdin: the instance's validator digest JSON)
  validator-check  print the policy shapes the validator must reject
  report           read stage results (stdin JSON) and print the report
"""
import copy
import errno
import json
from pathlib import Path
import sys
import time

HERE = Path(__file__).resolve().parent
REPORT_VERSION = 'agentgate.kernel-verification.v1'
WORKSPACE = '/var/lib/agentgate/workspace'

# Each check: what the agent does inside the guarded launch, and the outcome
# that counts as a pass. "denied" passes only with a permission errno.
CHECKS = [
    ('read_allowed', 'allowed', 'read a