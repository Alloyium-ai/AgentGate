#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Dan Metcalf
"""Owned diagnostic: query one public A name through a pinned TLS DNS endpoint."""
import hashlib
import ipaddress
import json
import secrets
import socket
import ssl
import struct
import sys

hostname, ca_path, resolver_address, resolver_name, evidence_path = sys.argv[1:]
hostname = hostname.encode("idna").decode("ascii")
if not hostname or hostname != hostname.lower() or len(hostname) > 253:
    raise ValueError("invalid hostname")
ipaddress.ip_address(resolver_address)
question_id = secrets.randbelow(65536)
name = b"".join(bytes([len(label)]) + label.encode("ascii") for label in hostname.split(".")) + b"\x00"
question = name + struct.pack("!HH", 1, 1)
query = struct.pack("!HHHHHH", question_id, 0x0100, 1, 0, 0, 0) + question
context = ssl.create_default_context(cafile=ca_path)
with socket.create_connection((resolver_address, 853), timeout=4) as tcp:
    with context.wrap_socket(tcp, server_hostname=resolver_name) as tls:
        tls.settimeout(4)
        tls.sendall(struct.pack("!H", len(query)) + query)
        length = tls.recv(2)
        if len(length) != 2:
            raise RuntimeError("short DNS frame")
        needed = struct.unpack("!H", length)[0]
        if needed > 4096:
            raise RuntimeError("oversized DNS frame")
        data = b""
        while len(data) < needed:
            chunk = tls.recv(needed - len(data))
            if not chunk:
                raise RuntimeError("incomplete DNS frame")
            data += chunk
        certificate = hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()

ident, flags, questions, answers, _, _ = struct.unpack_from("!HHHHHH", data)
if ident != question_id or flags & 0x800F != 0x8000 or questions != 1:
    raise RuntimeError("unexpected DNS response")


def skip_name(offset):
    while True:
        size = data[offset]
        if size & 0xC0 == 0xC0:
            return offset + 2
        offset += 1
        if size == 0:
            return offset
        if size & 0xC0 or offset + size > len(data):
            raise RuntimeError("invalid DNS name")
        offset += size


offset = skip_name(12) + 4
addresses = set()
for _ in range(answers):
    offset = skip_name(offset)
    kind, family, _, size = struct.unpack_from("!HHIH", data, offset)
    offset += 10
    value = data[offset:offset + size]
    offset += size
    if kind == 1 and family == 1 and size == 4:
        address = ipaddress.IPv4Address(value)
        if not address.is_global:
            raise RuntimeError("private DNS result")
        addresses.add(str(address))
if not addresses:
    raise RuntimeError("no public A result")
with open(evidence_path, "x", encoding="utf-8") as output:
    json.dump({"name": hostname, "resolver": f"{resolver_address}:853", "server_name": resolver_name,
               "tls_peer_sha256": certificate, "addresses": sorted(addresses)}, output)
for address in sorted(addresses):
    print(address)
