// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package pocpolicy

import (
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"alloyium.local/kernel-poc/internal/netrules"
)

// These digests were computed before the broker section existed. A document
// without a broker must keep them byte for byte: profiles, receipts and
// approvals refer to them.
const (
	exampleDigest        = "655058c968e5fad7a4a093ede811a94ce5aadca9aa2915706ad61354768fd6b3"
	fullExampleDigest    = "5e333ff9b0577d73abae4735cfdbdbeaba91d1abe16f28cf1525ed2c535973e0"
	sessionLaunchDigest  = "93d571cf57b5971d4473f5921329b952f6fe009c8bbbaa947a4b76266fcf2a91"
	oneshotLaunchDigest  = "a735305559ad4f409a784bacc19b65bd286b12f4e051fb858bb57be3afda7142"
	testBrokerAddress    = "172.30.7.2"
	testBrokerPort       = 8443
	testBrokerNeighbour  = "172.30.7.3"
	testBrokerGateway    = "172.30.7.1"
	exampleTaskboardAddr = "10.10.10.10"
)

func brokerLaunch(t *testing.T) Document {
	t.Helper()
	d, err := fullExample(t).ForLaunch(ModeSession, 3600)
	if err != nil {
		t.Fatal(err)
	}
	d, err = d.WithBroker(testBrokerAddress, testBrokerPort)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestDocumentsWithoutABrokerKeepTheirDigests(t *testing.T) {
	if got := fixture(t).Digest(); got != exampleDigest {
		t.Fatalf("version one example digest changed: %s", got)
	}
	full := fullExample(t)
	if got := full.Digest(); got != fullExampleDigest {
		t.Fatalf("version two example digest changed: %s", got)
	}
	session, err := full.ForLaunch(ModeSession, 3600)
	if err != nil || session.Digest() != sessionLaunchDigest {
		t.Fatalf("session launch digest changed: %v %s", err, session.Digest())
	}
	oneshot, err := full.ForLaunch(ModeOneshot, 30)
	if err != nil || oneshot.Digest() != oneshotLaunchDigest {
		t.Fatalf("oneshot launch digest changed: %v %s", err, oneshot.Digest())
	}
	for _, d := range []Document{fixture(t), full, session} {
		raw, _ := json.Marshal(d)
		if strings.Contains(string(raw), `"broker"`) || !strings.Contains(string(raw), `"taskboard"`) {
			t.Fatalf("a taskboard document changed shape: %s", raw)
		}
	}
}

func TestBrokerTakesTheSingleExactEndpoint(t *testing.T) {
	d := brokerLaunch(t)
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"taskboard"`) || !strings.Contains(string(raw), `"broker":{"address":"172.30.7.2","protocol":"tcp","port":8443}`) {
		t.Fatalf("broker document shape: %s", raw)
	}
	again, err := Parse(raw)
	if err != nil || again.Digest() != d.Digest() {
		t.Fatalf("a broker document does not round trip: %v", err)
	}
	if d.Digest() == sessionLaunchDigest {
		t.Fatal("the digest does not cover the broker endpoint")
	}
	other, _ := fullExample(t).ForLaunch(ModeSession, 3600)
	other, _ = other.WithBroker("172.30.7.10", testBrokerPort)
	if other.Digest() == d.Digest() {
		t.Fatal("two broker endpoints share a digest")
	}
	if e := d.Endpoint(); e.Kind != "broker" || e.Address != testBrokerAddress || e.Port != testBrokerPort || e.RuleID != "broker-exact" {
		t.Fatalf("endpoint %+v", e)
	}
	if e := fixture(t).Endpoint(); e.Kind != "taskboard" || e.Address != exampleTaskboardAddr || e.RuleID != "taskboard-exact" {
		t.Fatalf("taskboard endpoint %+v", e)
	}
	c, err := d.Compile(1, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(c.RuleIDs, "broker-exact") || slices.Contains(c.RuleIDs, "taskboard-exact") {
		t.Fatalf("rule ids %v", c.RuleIDs)
	}
	want := netip.MustParseAddr(testBrokerAddress).As4()
	if c.Policy.PilotMode != 1 || c.Policy.PilotFamily != netrules.IPv4 || c.Policy.PilotPort != testBrokerPort ||
		[4]byte(c.Policy.PilotAddress[:4]) != want {
		t.Fatalf("pilot %+v", c.Policy)
	}
	cases := []struct {
		ip      string
		proto   uint8
		port    uint16
		allowed bool
	}{
		{testBrokerAddress, netrules.TCP, testBrokerPort, true},
		{testBrokerAddress, netrules.UDP, testBrokerPort, false},
		{testBrokerAddress, netrules.TCP, testBrokerPort + 1, false},
		{testBrokerAddress, netrules.TCP, 443, false},
		{testBrokerNeighbour, netrules.TCP, testBrokerPort, false},
		{testBrokerGateway, netrules.TCP, testBrokerPort, false},
		// The taskboard exception is gone in a broker launch.
		{"10.0.0.2", netrules.TCP, 8080, false},
		{"127.0.0.1", netrules.TCP, testBrokerPort, false},
		{"169.254.169.254", netrules.TCP, 80, false},
		{"192.168.1.1", netrules.TCP, 443, false},
		{"93.184.215.14", netrules.TCP, 443, true},
		{"1.1.1.1", netrules.UDP, 53, true},
	}
	for _, v := range cases {
		e := netrules.Endpoint{Address: netip.MustParseAddr(v.ip), Protocol: v.proto, Port: v.port}
		if got := netrules.Evaluate(c.Policy, e, 2); got.Allowed != v.allowed {
			t.Errorf("%+v: %+v", v, got)
		}
		if got := netrules.Evaluate(c.Policy, e, 100); got.Allowed {
			t.Errorf("expired allow: %+v", v)
		}
	}
}

func TestTaskboardAndBrokerAreMutuallyExclusive(t *testing.T) {
	both := brokerLaunch(t)
	both.Taskboard = fullExample(t).Taskboard
	if err := both.Validate(); err == nil || !strings.Contains(err.Error(), "not both") {
		t.Fatalf("taskboard and broker together: %v", err)
	}
	raw, _ := json.Marshal(both)
	if _, err := Parse(raw); err == nil {
		t.Fatal("a parsed document held the taskboard and a broker")
	}
	neither := brokerLaunch(t)
	neither.Broker = nil
	if neither.Validate() == nil {
		t.Fatal("a document without any exact endpoint validated")
	}
	profile := fullExample(t)
	profile.Taskboard, profile.Broker = Taskboard{}, &Broker{Address: testBrokerAddress, Protocol: "tcp", Port: testBrokerPort}
	if err := profile.Validate(); err == nil || !strings.Contains(err.Error(), "launch mode") {
		t.Fatalf("a profile document without a mode carried a broker: %v", err)
	}
	if _, err := fullExample(t).WithBroker(testBrokerAddress, testBrokerPort); err == nil {
		t.Fatal("WithBroker accepted a document without a launch mode")
	}
	if _, err := fixture(t).WithBroker(testBrokerAddress, testBrokerPort); err == nil {
		t.Fatal("a version one document accepted a broker")
	}
	// A legacy taskboard document is unaffected by an absent broker.
	if err := fixture(t).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestBrokerEndpointValidation(t *testing.T) {
	launch, _ := fullExample(t).ForLaunch(ModeOneshot, 60)
	bad := []struct {
		address  string
		protocol string
		port     int
	}{
		{"127.0.0.1", "tcp", 8443}, {"169.254.169.254", "tcp", 8443}, {"169.254.1.2", "tcp", 8443}, {"1.1.1.1", "tcp", 8443},
		{"100.64.0.2", "tcp", 8443}, {"172.030.7.2", "tcp", 8443}, {"fd00::2", "tcp", 8443}, {"::ffff:172.30.7.2", "tcp", 8443},
		{"172.30.7.2", "udp", 8443}, {"172.30.7.2", "", 8443}, {"172.30.7.2", "tcp", 80}, {"172.30.7.2", "tcp", 1023},
		{"172.30.7.2", "tcp", 0}, {"172.30.7.2", "tcp", 65536}, {"", "tcp", 8443}, {"0.0.0.0", "tcp", 8443},
	}
	for _, b := range bad {
		if ValidBrokerEndpoint(b.address, b.protocol, b.port) == nil {
			t.Errorf("accepted broker endpoint %+v", b)
		}
		d := launch
		d.Taskboard, d.Broker = Taskboard{}, &Broker{Address: b.address, Protocol: b.protocol, Port: b.port}
		if d.Validate() == nil {
			t.Errorf("document accepted broker endpoint %+v", b)
		}
	}
	for _, good := range []string{"10.20.30.2", "172.30.7.2", "192.168.200.2"} {
		if err := ValidBrokerEndpoint(good, "tcp", 8443); err != nil {
			t.Errorf("%s: %v", good, err)
		}
	}
	raw := []byte(`{"version":"agentgate.poc.v2","default":"deny","ipv6":"deny","mode":"oneshot","duration_seconds":60,
 "dns":{"resolvers":["1.1.1.1"],"protocols":["udp","tcp"],"port":53},"web":{"destination":"public-ipv4","rules":[]},
 "broker":{"address":"172.30.7.2","protocol":"tcp","port":8443,"surprise":1},
 "filesystem":{"workspace":"/var/lib/agentgate/workspace","scratch":[],"read_only":[],"execute":["/usr"],"devices":[],"deny":[],"memory":{"anonymous_execute":false}},
 "process":{"signals":["SIGTERM"]}}`)
	if _, err := Parse(raw); err == nil {
		t.Fatal("an unknown broker field was accepted")
	}
	if _, err := Parse([]byte(strings.Replace(string(raw), `,"surprise":1`, "", 1))); err != nil {
		t.Fatalf("a valid broker launch document: %v", err)
	}
}

func TestShortenNarrowsALaunchLifetimeOnly(t *testing.T) {
	launch, _ := fullExample(t).ForLaunch(ModeSession, 3600)
	short, err := launch.Shorten(ModeSession, 3599)
	if err != nil || short.DurationSeconds != 3599 || short.Digest() == launch.Digest() {
		t.Fatalf("shorten: %v %d", err, short.DurationSeconds)
	}
	if _, err := launch.Shorten(ModeSession, 3601); err == nil {
		t.Fatal("a launch lifetime was extended")
	}
	if _, err := launch.Shorten(ModeOneshot, 60); err == nil {
		t.Fatal("a launch changed its mode")
	}
	if _, err := launch.Shorten(ModeSession, 30); err == nil {
		t.Fatal("a session was shortened below its minimum")
	}
	if _, err := fullExample(t).Shorten(ModeSession, 20); err == nil {
		t.Fatal("a profile document was shortened as if it were a launch")
	}
	broker := brokerLaunch(t)
	short, err = broker.Shorten(ModeSession, 1800)
	if err != nil || short.Broker == nil || short.Broker.Address != testBrokerAddress {
		t.Fatalf("shortening lost the broker endpoint: %v", err)
	}
}
