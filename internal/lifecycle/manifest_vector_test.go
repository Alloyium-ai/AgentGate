// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package lifecycle

// The gateway test reads the same vector. Keep it in Go source for source-slice parity.
const manifestVectorJSON = `{
  "manifest": {
    "protocol": "agentgate.job.manifest.v1",
    "agent_kind": "codex",
    "runtime_version": "cross-language-vector",
    "executable": "/opt/agent/bin/codex",
    "executable_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "image_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "arguments": [
      "exec",
      "<input>& 🙂"
    ],
    "workspace": "/work/job",
    "environment": {
      "HOME": "/work/job",
      "PATH": "/opt/agent/bin:/usr/bin:/bin",
      "TMPDIR": "/work/job/cache"
    },
    "input_digest": "fec58d91cceaf468660c3e0646b163a1d7534d9c9ff2781269f368f824a3d0a1"
  },
  "serialized": "{\"protocol\":\"agentgate.job.manifest.v1\",\"agent_kind\":\"codex\",\"runtime_version\":\"cross-language-vector\",\"executable\":\"/opt/agent/bin/codex\",\"executable_digest\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"image_digest\":\"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"arguments\":[\"exec\",\"\\u003cinput\\u003e\\u0026\\u2028🙂\"],\"workspace\":\"/work/job\",\"environment\":{\"HOME\":\"/work/job\",\"PATH\":\"/opt/agent/bin:/usr/bin:/bin\",\"TMPDIR\":\"/work/job/cache\"},\"input_digest\":\"fec58d91cceaf468660c3e0646b163a1d7534d9c9ff2781269f368f824a3d0a1\"}",
  "digest": "ba8ac665cb6c16b3eb505841c098641804d4b8171c5a0ea6c6f4840ae7fdd769"
}
`
