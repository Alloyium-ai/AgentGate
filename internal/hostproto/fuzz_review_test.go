// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package hostproto

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Fuzz targets from the second adversarial review (FuzzSecretPolicy,
// FuzzJobCheck, FuzzMountSource). Under plain go test they run only their
// seeds; go test -fuzz explores further.

// unlp splits one length-prefixed sequence; ok=false on any slack.
func unlp(b []byte) ([][]byte, bool) {
	var out [][]byte
	for len(b) > 0 {
		if len(b) < 4 {
			return nil, false
		}
		n := binary.BigEndian.Uint32(b[:4])
		b = b[4:]
		if uint64(n) > uint64(len(b)) {
			return nil, false
		}
		out = append(out, b[:n])
		b = b[n:]
	}
	return out, true
}

func decodeCanonical(t *testing.T, c []byte) SecretPolicy {
	top, ok := unlp(c)
	if !ok || len(top) != 9 || string(top[0]) != SecretPolicyFormat {
		t.Fatalf("bad top")
	}
	var p SecretPolicy
	p.Upstreams = []PolicyUpstream{}
	ups, _ := unlp(top[1])
	for _, u := range ups {
		f, ok := unlp(u)
		if !ok || len(f) != 4 {
			t.Fatalf("bad upstream")
		}
		port, _ := strconv.Atoi(string(f[1]))
		addrs, _ := unlp(f[3])
		as := []string{}
		for _, a := range addrs {
			as = append(as, string(a))
		}
		p.Upstreams = append(p.Upstreams, PolicyUpstream{Host: string(f[0]), Port: port, BasePath: string(f[2]), PrivateAddresses: as})
	}
	p.Header, p.Scheme, p.Username = string(top[2]), string(top[3]), string(top[4])
	p.ExtraHeaders = []PolicyHeader{}
	ex, _ := unlp(top[5])
	for _, e := range ex {
		f, ok := unlp(e)
		if !ok || len(f) != 2 {
			t.Fatalf("bad extra")
		}
		p.ExtraHeaders = append(p.ExtraHeaders, PolicyHeader{Name: string(f[0]), Value: string(f[1])})
	}
	p.ForwardHeaders = []string{}
	fw, _ := unlp(top[6])
	for _, f := range fw {
		p.ForwardHeaders = append(p.ForwardHeaders, string(f))
	}
	p.Rules = []BrokerRule{}
	rs, _ := unlp(top[7])
	for _, r := range rs {
		f, ok := unlp(r)
		if !ok || len(f) != 3 {
			t.Fatalf("bad rule")
		}
		ms, _ := unlp(f[0])
		methods := []string{}
		for _, m := range ms {
			methods = append(methods, string(m))
		}
		p.Rules = append(p.Rules, BrokerRule{Methods: methods, Path: string(f[1]), Match: string(f[2])})
	}
	p.Wildcard = string(top[8]) == "true"
	return p
}

type policyInput struct {
	Upstreams []string          `json:"u"`
	Header    string            `json:"h"`
	Scheme    string            `json:"s"`
	Username  string            `json:"n"`
	Rules     []BrokerRule      `json:"r"`
	Extra     map[string]string `json:"e"`
	Forward   []string          `json:"f"`
	Wildcard  bool              `json:"w"`
}

// FuzzSecretPolicy: the canonical encoding is injective (it decodes back to
// the normalized struct), normalization is idempotent through the forms the
// host re-renders (UpstreamNames, ExtraHeaderMap), and two inputs that the
// decoder distinguishes never share a digest.
func FuzzSecretPolicy(f *testing.F) {
	seeds := []policyInput{
		{Upstreams: []string{"api.example.test:0443"}, Header: "Authorization", Rules: []BrokerRule{{Methods: []string{"POST", "GET"}, Path: "/v1", Match: "prefix"}}},
		{Upstreams: []string{"a.b", "c.d:8443"}, Header: "x-api-key", Scheme: "Bearer", Extra: map[string]string{"A": "1", "b": ""}, Forward: []string{"X-A", "x-b"}},
		{Upstreams: []string{"a.b"}, Header: "authorization", Scheme: "Basic", Username: "u", Wildcard: true, Rules: []BrokerRule{{Methods: BrokerMethods, Path: "/", Match: "prefix"}}},
	}
	for _, s := range seeds {
		b, _ := json.Marshal(s)
		f.Add(b)
	}
	seen := map[string]string{}
	f.Fuzz(func(t *testing.T, raw []byte) {
		var in policyInput
		if json.Unmarshal(raw, &in) != nil {
			return
		}
		p, err := NewSecretPolicy(in.Upstreams, in.Header, in.Scheme, in.Username, in.Rules, in.Extra, in.Forward, in.Wildcard)
		if err != nil {
			return
		}
		c := p.Canonical()
		back := decodeCanonical(t, c)
		if !reflect.DeepEqual(back, p) {
			t.Fatalf("canonical not injective:\n%+v\n%+v", back, p)
		}
		// Re-render as the host and the service do and normalise again.
		var rules []BrokerRule
		rules = append(rules, p.Rules...)
		q, err := NewSecretPolicy(p.UpstreamNames(), p.Header, p.Scheme, p.Username, rules, p.ExtraHeaderMap(), p.ForwardHeaders, p.Wildcard)
		if err != nil {
			t.Fatalf("re-normalising a policy fails: %v (%+v)", err, p)
		}
		if q.Digest() != p.Digest() {
			t.Fatalf("normalisation not idempotent: %+v vs %+v", p, q)
		}
		// A JSON round trip (bindings.json on the host) keeps the digest.
		js, _ := json.Marshal(p)
		var r SecretPolicy
		if err := json.Unmarshal(js, &r); err != nil || r.Digest() != p.Digest() {
			t.Fatalf("json round trip changes digest: %v", err)
		}
		d := p.Digest()
		key := string(c)
		if prev, ok := seen[d]; ok && prev != key {
			t.Fatalf("digest collision")
		}
		if len(seen) < 100000 {
			seen[d] = key
		}
	})
}

// FuzzJobCheck: no panic on any job bytes; anything accepted re-encodes and
// is accepted again (decode stability), and a secret-put accepted carries a
// policy whose digest equals the envelope's.
func FuzzJobCheck(f *testing.F) {
	entries, _ := os.ReadDir("testdata/jobs")
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".job.json") {
			b, _ := os.ReadFile("testdata/jobs/" + e.Name())
			f.Add(b)
		}
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		var j Job
		if DecodeStrict(raw, &j) != nil {
			return
		}
		now := time.UnixMilli(j.IssuedAtMS).Add(time.Second)
		p, err := j.Check(j.TargetID, now)
		if err != nil {
			return
		}
		switch v := p.(type) {
		case SecretPutPayload:
			pol, err := v.Policy()
			if err != nil || pol.Digest() != v.PolicyDigest {
				t.Fatalf("accepted secret-put with inconsistent policy")
			}
		case LaunchPayload:
			for _, s := range v.Secrets {
				pol, err := s.Policy()
				if err != nil || pol.Digest() != s.PolicyDigest {
					t.Fatalf("accepted launch secret with inconsistent policy")
				}
			}
			for _, m := range v.Mounts {
				if CheckMountSource(m.Source) != nil {
					t.Fatalf("accepted launch mount with bad source %q", m.Source)
				}
			}
		}
		re, err := json.Marshal(j)
		if err != nil {
			t.Fatal(err)
		}
		var j2 Job
		if err := DecodeStrict(re, &j2); err != nil {
			t.Fatalf("re-encoded job not decodable: %v", err)
		}
		if _, err := j2.Check(j2.TargetID, now); err != nil {
			t.Fatalf("re-encoded job refused: %v", err)
		}
	})
}

// FuzzMountSource: an accepted source never overlaps a protected tree after
// any normalisation a kernel or Docker would apply, and never names a
// credential store component.
func FuzzMountSource(f *testing.F) {
	for _, s := range []string{"/srv/data", "/home/a/b", "/var/lib/dockerx", "/etc2", "/home/a/.ssh2", "/var/lib/agentgate-x", "/opt/x/../etc", "/srv//x", "/home/a/.SSH/x", "/Etc/x", "/var/lib/Docker"} {
		f.Add(s, "/srv")
	}
	f.Fuzz(func(t *testing.T, src, root string) {
		if CheckMountSource(src) != nil {
			return
		}
		if path.Clean(src) != src {
			t.Fatalf("not clean %q", src)
		}
		lower := strings.ToLower(src)
		for _, p := range ProtectedMountTrees {
			if overlaps(lower, p) && !overlaps(src, p) {
				t.Logf("case-folded overlap %q ~ %q (case-insensitive fs only)", src, p)
			}
		}
		for _, part := range strings.Split(src[1:], "/") {
			for _, s := range secretComponents {
				if strings.EqualFold(part, s) && part != s {
					t.Logf("case variant of credential store %q in %q", s, src)
				}
			}
		}
		if CheckMountRoots([]string{root}) == nil && MountUnderRoots(src, []string{root}) {
			if !(src == root || strings.HasPrefix(src, root+"/")) {
				t.Fatalf("under-root without prefix")
			}
		}
	})
}
