package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// testState builds two exits and a relay in front of the first one.
func testState(t *testing.T) *State {
	t.Helper()
	st := newState()
	for _, name := range []string{"me", "anna"} {
		u, err := newUser(name)
		if err != nil {
			t.Fatal(err)
		}
		st.Users = append(st.Users, u)
	}
	for _, o := range []nodeOpts{
		{Name: "nl1", Address: "203.0.113.10", Target: "www.example.org:443", XHTTPPort: 443, VisionPort: 8443, Hy2Port: 443},
		{Name: "fi1", Address: "198.51.100.7", Target: "cdn.example.net:443", XHTTPPort: 443, VisionPort: 2053, Hy2Port: 443},
		{Name: "ru1", Address: "192.0.2.44", Target: "static.example.ru:443", Upstream: "nl1", XHTTPPort: 443, VisionPort: 8443},
	} {
		n, err := newNode(o)
		if err != nil {
			t.Fatal(err)
		}
		st.Nodes = append(st.Nodes, n)
	}
	if err := st.validate(); err != nil {
		t.Fatal(err)
	}
	return st
}

// roundTrip turns a config into what Xray would read from the file.
func roundTrip(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func find(t *testing.T, list any, tag string) map[string]any {
	t.Helper()
	for _, it := range list.([]any) {
		if m := it.(map[string]any); m["tag"] == tag {
			return m
		}
	}
	return nil
}

func dig(t *testing.T, m map[string]any, path ...string) any {
	t.Helper()
	var cur any = m
	for _, k := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("%v: %q is not an object", path, k)
		}
		cur = mm[k]
	}
	return cur
}

// RFC 7748 section 6.1: the public key must be the one every other X25519
// implementation derives, or REALITY and VLESS Encryption will not connect.
func TestX25519MatchesRFC7748(t *testing.T) {
	priv, _ := hex.DecodeString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	_, pub, err := x25519FromBytes(priv)
	if err != nil {
		t.Fatal(err)
	}
	got, err := base64.RawURLEncoding.DecodeString(pub)
	if err != nil {
		t.Fatal(err)
	}
	if want := "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"; hex.EncodeToString(got) != want {
		t.Fatalf("public key %x, want %s", got, want)
	}
}

func TestX25519PrivateKeyIsClamped(t *testing.T) {
	for i := 0; i < 32; i++ {
		priv, _, err := newX25519()
		if err != nil {
			t.Fatal(err)
		}
		b, err := base64.RawURLEncoding.DecodeString(priv)
		if err != nil || len(b) != 32 {
			t.Fatalf("private key %q: %v, %d bytes", priv, err, len(b))
		}
		if b[0]&7 != 0 || b[31]&0x80 != 0 || b[31]&0x40 == 0 {
			t.Fatalf("private key not clamped: %x", b)
		}
	}
}

// xrayAcceptsEnc mirrors the check Xray v26.11.9 applies to the VLESS
// "decryption" and "encryption" strings (infra/conf/vless.go).
func xrayAcceptsEnc(s string, third func(string) bool) bool {
	parts := strings.Split(s, ".")
	if len(parts) < 4 || parts[0] != "mlkem768x25519plus" || parts[1] != "native" || !third(parts[2]) {
		return false
	}
	for _, r := range parts[3:] {
		if len(r) < 20 {
			continue
		}
		if b, _ := base64.RawURLEncoding.DecodeString(r); len(b) != 32 {
			return false
		}
	}
	return true
}

func TestVLESSEncryptionStrings(t *testing.T) {
	n := testState(t).Nodes[0]
	if !xrayAcceptsEnc(n.decryption(), func(s string) bool { return s == "600s" }) {
		t.Errorf("decryption %q is not what Xray accepts", n.decryption())
	}
	if !xrayAcceptsEnc(n.encryption(), func(s string) bool { return s == "0rtt" }) {
		t.Errorf("encryption %q is not what Xray accepts", n.encryption())
	}
	// The two halves must belong to one key pair.
	priv, _ := base64.RawURLEncoding.DecodeString(n.XHTTP.EncPrivate)
	if _, pub, _ := x25519FromBytes(priv); pub != n.XHTTP.EncPublic {
		t.Errorf("encryption public key does not match the private key")
	}
}

func TestUUIDIsVersion4(t *testing.T) {
	id, err := newUUID()
	if err != nil {
		t.Fatal(err)
	}
	if len(id) != 36 || id[14] != '4' || !strings.ContainsRune("89ab", rune(id[19])) {
		t.Fatalf("not a v4 UUID: %s", id)
	}
}

func TestExitServerConfig(t *testing.T) {
	st := testState(t)
	nl := st.node("nl1")
	c := roundTrip(t, serverConfig(st, nl))

	x := find(t, c["inbounds"], kindXHTTP)
	if x == nil || find(t, c["inbounds"], kindVision) == nil || find(t, c["inbounds"], kindHy2) == nil {
		t.Fatal("exit must serve xhttp, vision and hy2")
	}
	// Two users plus the identity of the relay that forwards here.
	users := dig(t, x, "settings", "users").([]any)
	if len(users) != 3 {
		t.Fatalf("xhttp users = %d, want 3", len(users))
	}
	ids := map[string]bool{}
	for _, u := range users {
		um := u.(map[string]any)
		ids[um["id"].(string)] = true
		if um["flow"] != visionFlow {
			t.Errorf("xhttp user without vision flow: %v", um)
		}
	}
	if !ids[st.node("ru1").LinkUUID] {
		t.Error("the relay's identity is missing from its upstream")
	}
	// Xray rejects "fallbacks" next to VLESS Encryption.
	if _, ok := dig(t, x, "settings").(map[string]any)["fallbacks"]; ok {
		t.Error("xhttp inbound must not carry fallbacks")
	}
	if dig(t, x, "streamSettings", "realitySettings", "target") != "www.example.org:443" {
		t.Error("wrong REALITY target")
	}
	if dig(t, c, "log", "access") != "none" {
		t.Error("server must not keep an access log")
	}

	// The relay's identity opens only the transport the relay uses.
	v := find(t, c["inbounds"], kindVision)
	if n := len(dig(t, v, "settings", "users").([]any)); n != 2 {
		t.Errorf("vision users = %d, want 2", n)
	}
	if dig(t, v, "settings", "decryption") != "none" {
		t.Error("vision runs over REALITY alone")
	}

	if got := c["outbounds"].([]any)[0].(map[string]any)["protocol"]; got != "freedom" {
		t.Errorf("exit default outbound = %v, want freedom", got)
	}
	if !routes(c, "geoip:ru", "block") || !routes(c, "geosite:category-ru", "block") {
		t.Error("exit must refuse Russian destinations by default")
	}

	nl.AllowRU = true
	if c = roundTrip(t, serverConfig(st, nl)); routes(c, "geoip:ru", "block") {
		t.Error("allow_ru must lift the block")
	}
}

// routes reports whether some rule sends the matcher to the outbound.
func routes(c map[string]any, matcher, outbound string) bool {
	rules := c["routing"].(map[string]any)["rules"].([]any)
	for _, r := range rules {
		rm := r.(map[string]any)
		if rm["outboundTag"] != outbound {
			continue
		}
		for _, key := range []string{"ip", "domain"} {
			if list, ok := rm[key].([]any); ok {
				for _, v := range list {
					if v == matcher {
						return true
					}
				}
			}
		}
	}
	return false
}

func TestRelayServerConfig(t *testing.T) {
	st := testState(t)
	ru, nl := st.node("ru1"), st.node("nl1")
	c := roundTrip(t, serverConfig(st, ru))

	if find(t, c["inbounds"], kindHy2) != nil {
		t.Error("hy2 was disabled on the relay and must not be served")
	}
	up := c["outbounds"].([]any)[0].(map[string]any)
	if up["tag"] != "upstream" {
		t.Fatalf("relay default outbound = %v, want upstream", up["tag"])
	}
	if dig(t, up, "settings", "id") != ru.LinkUUID {
		t.Error("relay must use its own identity upstream")
	}
	if dig(t, up, "settings", "address") != nl.Address {
		t.Error("relay points at the wrong exit")
	}
	if dig(t, up, "streamSettings", "realitySettings", "password") != nl.Reality.PublicKey {
		t.Error("relay uses the wrong REALITY key for its exit")
	}
	if dig(t, up, "streamSettings", "network") != "xhttp" {
		t.Error("the relay link must be xhttp")
	}
	// A Russian service the relay fetched a page from would see the relay's
	// own address, the one clients connect to.
	if !routes(c, "geoip:ru", "block") || !routes(c, "geosite:category-ru", "block") {
		t.Error("relay must refuse Russian destinations by default")
	}

	ru.AllowRU = true
	c = roundTrip(t, serverConfig(st, ru))
	if !routes(c, "geoip:ru", "direct") || !routes(c, "geosite:category-ru", "direct") {
		t.Error("with allow_ru the relay must serve Russian destinations itself")
	}
	if routes(c, "geoip:ru", "block") {
		t.Error("allow_ru must lift the block on the relay")
	}
}

// A relay with several exits moves to a live one by itself. A client pinned to
// the relay, a phone as much as a computer, then has nothing to do when an
// exit is banned.
func TestRelayPicksAmongSeveralExits(t *testing.T) {
	st := testState(t)
	ru, nl, fi := st.node("ru1"), st.node("nl1"), st.node("fi1")
	ru.Upstream = "nl1,fi1"
	if err := st.validate(); err != nil {
		t.Fatal(err)
	}
	c := roundTrip(t, serverConfig(st, ru))

	for _, want := range []struct {
		tag  string
		exit *Node
	}{{"nl1-up", nl}, {"fi1-up", fi}} {
		o := find(t, c["outbounds"], want.tag)
		if o == nil {
			t.Fatalf("relay has no outbound %s", want.tag)
		}
		if dig(t, o, "settings", "address") != want.exit.Address || dig(t, o, "settings", "id") != ru.LinkUUID ||
			dig(t, o, "streamSettings", "realitySettings", "password") != want.exit.Reality.PublicKey {
			t.Errorf("%s does not lead to %s under the relay's own identity", want.tag, want.exit.Name)
		}
	}

	bal := dig(t, c, "routing", "balancers").([]any)[0].(map[string]any)
	if got := fmt.Sprint(bal["selector"]); got != "[nl1-up fi1-up]" {
		t.Errorf("balancer picks among %s, want the exits in the order given", got)
	}
	if bal["fallbackTag"] != "nl1-up" {
		t.Errorf("fallback = %v, want the first exit", bal["fallbackTag"])
	}
	costs := dig(t, bal, "strategy", "settings", "costs").([]any)
	if len(costs) != 2 || costs[0].(map[string]any)["value"].(float64) >= costs[1].(map[string]any)["value"].(float64) {
		t.Errorf("costs = %v, want the first exit preferred", costs)
	}
	rules := dig(t, c, "routing", "rules").([]any)
	if last := rules[len(rules)-1].(map[string]any); last["balancerTag"] != bal["tag"] {
		t.Errorf("last rule = %v, want everything left sent to the balancer", last)
	}
	if !routes(c, "geoip:ru", "block") {
		t.Error("Russian destinations must be refused before the balancer sees them")
	}

	// The relay notices a dead exit the way a client notices a dead node.
	auto := roundTrip(t, autoClient(profiles(st, st.user("me"))))
	clientBal := dig(t, auto, "routing", "balancers").([]any)[0].(map[string]any)
	if dig(t, bal, "strategy", "settings").(map[string]any)["tolerance"] != dig(t, clientBal, "strategy", "settings").(map[string]any)["tolerance"] ||
		!reflect.DeepEqual(dig(t, c, "burstObservatory", "pingConfig"), dig(t, auto, "burstObservatory", "pingConfig")) {
		t.Error("relay and client must check nodes and drop them by the same rule")
	}
	if got := fmt.Sprint(dig(t, c, "burstObservatory", "subjectSelector")); got != "[nl1-up fi1-up]" {
		t.Errorf("health checks cover %s, want both exits", got)
	}

	// Every exit on the list lets the relay in.
	for _, exit := range []*Node{nl, fi} {
		x := find(t, roundTrip(t, serverConfig(st, exit))["inbounds"], kindXHTTP)
		known := false
		for _, u := range dig(t, x, "settings", "users").([]any) {
			known = known || u.(map[string]any)["id"] == ru.LinkUUID
		}
		if !known {
			t.Errorf("exit %s does not know the relay", exit.Name)
		}
	}
}

// Changing a relay's exits must not touch its keys: clients keep the profiles
// they have, which is the point of doing it without removing the relay.
func TestRotateUpstreamKeepsRelayKeys(t *testing.T) {
	st := testState(t)
	path := filepath.Join(t.TempDir(), "obhod.json")
	if err := st.save(path); err != nil {
		t.Fatal(err)
	}
	before := *st.node("ru1")

	if err := run([]string{"node", "rotate", "-state", path, "-name", "ru1", "-upstream", "fi1,nl1"}); err != nil {
		t.Fatal(err)
	}
	got, err := loadState(path)
	if err != nil {
		t.Fatal(err)
	}
	after := got.node("ru1")
	if after.Upstream != "fi1,nl1" {
		t.Errorf("upstream = %q, want fi1,nl1", after.Upstream)
	}
	if after.LinkUUID != before.LinkUUID || after.Reality != before.Reality || after.XHTTP != before.XHTTP {
		t.Error("the relay's keys changed")
	}

	// An exit turned into a relay would leave clients with profiles for a
	// node that no longer exits anywhere.
	err = run([]string{"node", "rotate", "-state", path, "-name", "nl1", "-upstream", "fi1"})
	if err == nil || !strings.Contains(err.Error(), "is an exit") {
		t.Errorf("exit given an upstream: err = %v", err)
	}
	if err := run([]string{"node", "rotate", "-state", path, "-name", "ru1", "-upstream", "fi1,gone"}); err == nil {
		t.Error("an upstream that does not exist was accepted")
	}
}

// The burst rule freezes a client that opens more than three TLS handshakes
// to one name within a minute, so XHTTP must stay within that many
// connections. Xray also refuses maxConnections together with maxConcurrency.
func TestXmuxStaysUnderBurstRule(t *testing.T) {
	m := xmux()
	if n := m["maxConnections"].(int); n < 1 || n > 3 {
		t.Errorf("maxConnections = %d, want 1..3", n)
	}
	if _, ok := m["maxConcurrency"]; ok {
		t.Error("maxConcurrency cannot be combined with maxConnections")
	}
	for _, k := range []string{"cMaxReuseTimes", "hMaxRequestTimes", "hMaxReusableSecs", "hKeepAlivePeriod"} {
		if _, ok := m[k]; !ok {
			t.Errorf("xmux.%s must be explicit: setting any field drops Xray's defaults", k)
		}
	}
}

func TestClientOutbounds(t *testing.T) {
	st := testState(t)
	me := st.user("me")
	ps := profiles(st, me)

	var tags []string
	for _, p := range ps {
		tags = append(tags, p.Tag)
	}
	want := "nl1-xhttp nl1-vision nl1-hy2 fi1-xhttp fi1-vision fi1-hy2 ru1-xhttp ru1-vision"
	if got := strings.Join(tags, " "); got != want {
		t.Fatalf("profiles = %s\n      want %s", got, want)
	}

	x := roundTrip(t, ps[0].Outbound)
	if dig(t, x, "settings", "id") != me.UUID || dig(t, x, "settings", "flow") != visionFlow {
		t.Error("xhttp outbound: wrong id or flow")
	}
	if dig(t, x, "streamSettings", "xhttpSettings", "mode") != "stream-one" {
		t.Error("xhttp outbound must use stream-one")
	}
	if dig(t, x, "streamSettings", "realitySettings", "fingerprint") != defaultFingerprint {
		t.Error("xhttp outbound: wrong fingerprint")
	}
	// A client config that names a target would be parsed as a server.
	if _, ok := dig(t, x, "streamSettings", "realitySettings").(map[string]any)["target"]; ok {
		t.Error("client REALITY settings must not contain target")
	}

	h := roundTrip(t, ps[2].Outbound)
	if dig(t, h, "protocol") != "hysteria" || dig(t, h, "streamSettings", "security") != "tls" {
		t.Error("hy2 outbound: wrong protocol or security")
	}
	if dig(t, h, "streamSettings", "tlsSettings", "pinnedPeerCertSha256") != st.node("nl1").Hy2.CertSHA256 {
		t.Error("hy2 outbound must pin the node's certificate")
	}
	if _, ok := dig(t, h, "streamSettings", "tlsSettings").(map[string]any)["allowInsecure"]; ok {
		t.Error("hy2 outbound must pin, not disable verification")
	}
}

func TestAutoClientProbesOnlyXHTTP(t *testing.T) {
	st := testState(t)
	c := roundTrip(t, autoClient(profiles(st, st.user("me"))))

	bal := dig(t, c, "routing", "balancers").([]any)[0].(map[string]any)
	sel := bal["selector"].([]any)
	if len(sel) != 3 {
		t.Fatalf("selector = %v, want the three xhttp profiles", sel)
	}
	for _, s := range sel {
		if !strings.HasSuffix(s.(string), "-"+kindXHTTP) {
			t.Errorf("%v must not be probed in the background", s)
		}
	}
	if bal["fallbackTag"] != "nl1-xhttp" {
		t.Errorf("fallback = %v, want the first exit", bal["fallbackTag"])
	}
	// Exits in the order given, relays last: each must cost more than the one before.
	costs := dig(t, bal, "strategy", "settings", "costs").([]any)
	order := []string{"nl1-xhttp", "fi1-xhttp", "ru1-xhttp"}
	prev := 0.0
	for i, c := range costs {
		cm := c.(map[string]any)
		if cm["match"] != order[i] {
			t.Fatalf("cost %d is for %v, want %s", i, cm["match"], order[i])
		}
		if v := cm["value"].(float64); v <= prev {
			t.Errorf("%s costs %v, not more than the profile before it", order[i], v)
		} else {
			prev = v
		}
	}
	for _, o := range c["outbounds"].([]any) {
		tag := o.(map[string]any)["tag"].(string)
		if strings.HasSuffix(tag, "-"+kindVision) || strings.HasSuffix(tag, "-"+kindHy2) {
			t.Errorf("auto config carries %s", tag)
		}
	}
	if got := dig(t, c, "burstObservatory", "subjectSelector").([]any); len(got) != 3 {
		t.Errorf("observatory watches %v", got)
	}
	// Whatever is not Russian or local goes to the balancer.
	rules := dig(t, c, "routing", "rules").([]any)
	if last := rules[len(rules)-1].(map[string]any); last["balancerTag"] != "auto" {
		t.Errorf("last rule = %v", last)
	}
	if !routes(c, "geoip:ru", "direct") {
		t.Error("Russian destinations must go direct")
	}
}

// How Xray decides a node is dead (app/observatory/burst, strategy_leastload):
// every node is checked `sampling` times, at random moments, within each
// window of interval × sampling, and the last `sampling` results are kept.
// Left alone, the balancer drops a node only when every kept result is a
// failure. With four results a minute apart, a silently banned exit held all
// the traffic: 166 seconds without a switch in a lab run, with a healthy
// second exit standing by.
func TestAutoClientDropsDeadNode(t *testing.T) {
	st := testState(t)
	c := roundTrip(t, autoClient(profiles(st, st.user("me"))))
	ping := dig(t, c, "burstObservatory", "pingConfig").(map[string]any)
	interval, err := time.ParseDuration(ping["interval"].(string))
	if err != nil {
		t.Fatal(err)
	}
	sampling := ping["sampling"].(float64)
	bal := dig(t, c, "routing", "balancers").([]any)[0].(map[string]any)
	tolerance, _ := dig(t, bal, "strategy", "settings").(map[string]any)["tolerance"].(float64)

	// Two failed checks among the kept ones take a node out. One does not,
	// even while only two results exist: the first check through a fresh
	// XHTTP connection is slow and now and then times out on a healthy node,
	// and a single lost check must not move a user to another exit address.
	if tolerance < 0.5 || tolerance >= 2/sampling {
		t.Errorf("tolerance %v with %v kept results: want one failure of two tolerated, two of %v not", tolerance, sampling, sampling)
	}
	// A window is the longest a dead node can go with one check or none.
	if window := time.Duration(sampling) * interval; window > 2*time.Minute {
		t.Errorf("checks are spread over %v: too long to notice a dead node", window)
	}
	// Every check of a dead node is a fresh TLS handshake, and more than
	// three a minute to one name set off the burst rule. Real traffic dials
	// too, so the checks take at most two.
	if perMinute := float64(time.Minute) / float64(interval); perMinute > 2 {
		t.Errorf("%.1f checks a minute per node: too close to the burst rule", perMinute)
	}
}

// A phone app brings the tunnel interface itself: v2rayNG adds one to a config
// it imports. A local proxy port there would only be a way for other apps to
// find the tunnel, so the phone config listens on nothing. In everything else
// it is the config a computer fails over with.
func TestMobileClientOpensNoLocalPort(t *testing.T) {
	st := testState(t)
	ps := profiles(st, st.user("me"))
	auto, phone := roundTrip(t, autoClient(ps)), roundTrip(t, mobileClient(ps))
	if in, ok := phone["inbounds"].([]any); !ok || len(in) != 0 {
		t.Errorf("phone config inbounds = %v, want an empty list", phone["inbounds"])
	}
	delete(auto, "inbounds")
	delete(phone, "inbounds")
	if !reflect.DeepEqual(auto, phone) {
		t.Error("the phone must pick nodes exactly as the computer does")
	}

	st.Nodes = st.Nodes[:1]
	if c := mobileClient(profiles(st, st.user("me"))); c != nil {
		t.Error("with one xhttp profile there is nothing to fail over to: the phone imports the link")
	}
}

func TestSingleClientRouting(t *testing.T) {
	st := testState(t)
	for _, p := range profiles(st, st.user("me")) {
		c := roundTrip(t, singleClient(p))
		rules := dig(t, c, "routing", "rules").([]any)
		if last := rules[len(rules)-1].(map[string]any); last["outboundTag"] != p.Tag {
			t.Errorf("%s: last rule = %v", p.Tag, last)
		}
		if !routes(c, "geoip:private", "direct") {
			t.Errorf("%s: LAN must stay direct", p.Tag)
		}
		// A Russian service reached through a node learns the node's address.
		if !routes(c, "geoip:ru", "direct") || !routes(c, "geosite:category-ru", "direct") {
			t.Errorf("%s: Russian destinations must go direct", p.Tag)
		}
	}
}

// On a whitelist-only network a direct connection to a Russian site that is
// not on the list fails. A relay marked allow_ru reaches it from inside, so
// the configs pinned to that relay send it everything.
func TestSingleClientRoutingThroughRelayThatServesRussia(t *testing.T) {
	st := testState(t)
	st.node("ru1").AllowRU = true
	for _, p := range profiles(st, st.user("me")) {
		c := roundTrip(t, singleClient(p))
		if got, want := routes(c, "geoip:ru", "direct"), !p.Node.IsRelay(); got != want {
			t.Errorf("%s: Russian destinations direct = %v, want %v", p.Tag, got, want)
		}
		if !routes(c, "geoip:private", "direct") {
			t.Errorf("%s: LAN must stay direct", p.Tag)
		}
	}
}

// clientConfigs returns every desktop config rendered for the user, by name.
func clientConfigs(t *testing.T, st *State, user string) map[string]map[string]any {
	t.Helper()
	ps := profiles(st, st.user(user))
	out := map[string]map[string]any{"auto": roundTrip(t, autoClient(ps))}
	for _, p := range ps {
		out[p.Tag] = roundTrip(t, singleClient(p))
	}
	return out
}

// Any program on the machine can connect to 127.0.0.1. Through an open local
// proxy it sends one request and learns the address the tunnel exits from.
func TestLocalProxyNeedsPassword(t *testing.T) {
	st := testState(t)
	pass := map[string]string{}
	for _, user := range []string{"me", "anna"} {
		for name, c := range clientConfigs(t, st, user) {
			for _, in := range c["inbounds"].([]any) {
				im := in.(map[string]any)
				where := name + "/" + im["tag"].(string)
				if im["listen"] != "127.0.0.1" {
					t.Errorf("%s listens on %v", where, im["listen"])
				}
				set, _ := im["settings"].(map[string]any)
				accounts, _ := set["accounts"].([]any)
				if len(accounts) != 1 {
					t.Errorf("%s: accounts = %v, want exactly one", where, accounts)
					continue
				}
				a := accounts[0].(map[string]any)
				p, _ := a["pass"].(string)
				if a["user"] != user || len(p) < 16 {
					t.Errorf("%s: account %v, want user %q and a long password", where, a, user)
				}
				// Xray's SOCKS inbound ignores accounts unless auth says so.
				if im["protocol"] == "socks" && set["auth"] != "password" {
					t.Errorf("%s: auth = %v, want password", where, set["auth"])
				}
				pass[user] = p
			}
		}
	}
	if pass["me"] == pass["anna"] {
		t.Errorf("two users share the local proxy password %q", pass["me"])
	}
}

// A program looking for a tunnel tries Xray's stock ports first. And a port
// the OS hands out for outgoing connections is now and then already taken.
func TestLocalProxyPortsAreNotStock(t *testing.T) {
	st := testState(t)
	seen := map[string]float64{}
	for name, c := range clientConfigs(t, st, "me") {
		for _, in := range c["inbounds"].([]any) {
			im := in.(map[string]any)
			tag, port := im["tag"].(string), im["port"].(float64)
			if port == 10808 || port == 10809 || port < 1024 || port >= 32768 {
				t.Errorf("%s/%s listens on port %v", name, tag, port)
			}
			// One address per user, whichever config is running.
			if p, ok := seen[tag]; ok && p != port {
				t.Errorf("%s/%s listens on port %v, another config on %v", name, tag, port, p)
			}
			seen[tag] = port
		}
	}
	if seen["socks"] == seen["http"] {
		t.Errorf("socks and http share port %v", seen["socks"])
	}
}

func TestAutoClientNeedsTwoProfiles(t *testing.T) {
	st := testState(t)
	st.Nodes = st.Nodes[:1]
	if c := autoClient(profiles(st, st.user("me"))); c != nil {
		t.Error("one xhttp profile leaves nothing to fail over to")
	}
}

func TestShareLinks(t *testing.T) {
	st := testState(t)
	me, nl := st.user("me"), st.node("nl1")
	ps := profiles(st, me)

	u, err := url.Parse(ps[0].Link)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Scheme != "vless" || u.User.Username() != me.UUID || u.Host != "203.0.113.10:443" || u.Fragment != "nl1-xhttp" {
		t.Errorf("xhttp link: %s", ps[0].Link)
	}
	for k, want := range map[string]string{
		"type": "xhttp", "security": "reality", "mode": "stream-one", "flow": visionFlow,
		"sni": "www.example.org", "fp": defaultFingerprint, "pbk": nl.Reality.PublicKey,
		"sid": nl.Reality.ShortID, "path": nl.XHTTP.Path, "encryption": nl.encryption(),
	} {
		if q.Get(k) != want {
			t.Errorf("xhttp link %s = %q, want %q", k, q.Get(k), want)
		}
	}
	var extra struct {
		Xmux map[string]any `json:"xmux"`
	}
	if err := json.Unmarshal([]byte(q.Get("extra")), &extra); err != nil || extra.Xmux["maxConnections"] != float64(2) {
		t.Errorf("xhttp link extra = %q (%v)", q.Get("extra"), err)
	}

	u, _ = url.Parse(ps[1].Link)
	q = u.Query()
	if u.Host != "203.0.113.10:8443" || q.Get("type") != "tcp" || q.Get("encryption") != "none" || q.Get("flow") != visionFlow {
		t.Errorf("vision link: %s", ps[1].Link)
	}

	u, _ = url.Parse(ps[2].Link)
	q = u.Query()
	if u.Scheme != "hysteria2" || u.User.Username() != me.Hy2Auth || q.Get("obfs") != "salamander" ||
		q.Get("obfs-password") != nl.Hy2.ObfsPassword || q.Get("pinSHA256") != nl.Hy2.CertSHA256 {
		t.Errorf("hy2 link: %s", ps[2].Link)
	}

	raw, err := base64.StdEncoding.DecodeString(subscription(ps))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != len(ps) || lines[0] != ps[0].Link {
		t.Errorf("subscription has %d lines for %d profiles", len(lines), len(ps))
	}
}

func TestIPv6AddressInLink(t *testing.T) {
	st := testState(t)
	st.node("nl1").Address = "2001:db8::10"
	u, err := url.Parse(profiles(st, st.user("me"))[0].Link)
	if err != nil {
		t.Fatal(err)
	}
	if u.Hostname() != "2001:db8::10" || u.Port() != "443" {
		t.Errorf("host %q port %q", u.Hostname(), u.Port())
	}
}

func TestStateValidation(t *testing.T) {
	bad := map[string]func(*State){
		"relay of a relay":             func(s *State) { s.node("nl1").Upstream = "fi1"; s.node("fi1").Upstream = "nl1" },
		"missing upstream":             func(s *State) { s.node("ru1").Upstream = "gone" },
		"one of the upstreams missing": func(s *State) { s.node("ru1").Upstream = "nl1,gone" },
		"upstream listed twice":        func(s *State) { s.node("ru1").Upstream = "nl1,nl1" },
		"empty name among upstreams":   func(s *State) { s.node("ru1").Upstream = "nl1," },
		"duplicate node":               func(s *State) { s.node("fi1").Name = "nl1" },
		"name with dash":               func(s *State) { s.node("fi1").Name = "fi-1" },
		"shared tcp port":              func(s *State) { s.node("fi1").Vision.Port = 443 },
		"nothing enabled":              func(s *State) { n := s.node("fi1"); n.XHTTP.Port, n.Vision.Port, n.Hy2.Port = 0, 0, 0 },
		"relay link gone":              func(s *State) { s.node("nl1").XHTTP.Port = 0 },
		"target no port":               func(s *State) { s.node("fi1").Reality.Target = "cdn.example.net" },
	}
	for name, mutate := range bad {
		st := testState(t)
		mutate(st)
		if err := st.validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestStateSaveLoad(t *testing.T) {
	st := testState(t)
	path := filepath.Join(t.TempDir(), "obhod.json")
	if err := st.save(path); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("state mode %o, want 600: it holds private keys", fi.Mode().Perm())
	}
	got, err := loadState(path)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(st)
	b, _ := json.Marshal(got)
	if string(a) != string(b) {
		t.Error("state changed across save and load")
	}
}

func TestRekeyReplacesEverySecret(t *testing.T) {
	n := testState(t).Nodes[0]
	before := *n
	if err := n.rekey(); err != nil {
		t.Fatal(err)
	}
	for name, pair := range map[string][2]string{
		"reality key": {before.Reality.PrivateKey, n.Reality.PrivateKey},
		"short id":    {before.Reality.ShortID, n.Reality.ShortID},
		"enc key":     {before.XHTTP.EncPrivate, n.XHTTP.EncPrivate},
		"xhttp path":  {before.XHTTP.Path, n.XHTTP.Path},
		"hy2 obfs":    {before.Hy2.ObfsPassword, n.Hy2.ObfsPassword},
		"hy2 cert":    {before.Hy2.CertSHA256, n.Hy2.CertSHA256},
	} {
		if pair[0] == pair[1] {
			t.Errorf("%s survived rekey", name)
		}
	}
	if n.Address != before.Address || n.Reality.Target != before.Reality.Target {
		t.Error("rekey must not move the node")
	}
}

// tlsSite runs a TLS server on loopback, set up the way some would-be target
// site is, and returns its address.
func tlsSite(t *testing.T, tune func(*tls.Config)) string {
	t.Helper()
	certPEM, keyPEM, _, err := newSelfSignedCert("target.test")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	conf := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}}
	tune(conf)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", conf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				c.(*tls.Conn).Handshake()
				c.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

// A site that answers `curl --tlsv1.3 --http2` can still be useless as a
// REALITY target: an exit put behind one that takes only the P-256 key
// exchange failed every client with "invalid server key share".
func TestTargetProblem(t *testing.T) {
	for _, c := range []struct {
		name string
		tune func(*tls.Config)
		want string // a part of the problem; empty means the site fits
	}{
		{"TLS 1.3, X25519, HTTP/2", func(*tls.Config) {}, ""},
		{"P-256 key exchange only", func(c *tls.Config) { c.CurvePreferences = []tls.CurveID{tls.CurveP256} }, "X25519"},
		{"no TLS 1.3", func(c *tls.Config) { c.MaxVersion = tls.VersionTLS12 }, "TLS 1.3"},
		{"no HTTP/2", func(c *tls.Config) { c.NextProtos = []string{"http/1.1"} }, "HTTP/2"},
	} {
		got := targetProblem(tlsSite(t, c.tune), "target.test", 5*time.Second)
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: problem = %q, want one about %q", c.name, got, c.want)
		}
	}

	// An unreachable site says nothing about the site: the machine running
	// ansibles may simply sit in a network that cannot see it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	free := ln.Addr().String()
	ln.Close()

	// A connection cut off mid-handshake is what a censor's filter looks like
	// from inside its network. It must not be blamed on the site.
	cut, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cut.Close() })
	go func() {
		for {
			c, err := cut.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	if got := targetProblem(cut.Addr().String(), "target.test", 5*time.Second); !strings.Contains(got, "не удалось проверить") {
		t.Errorf("connection cut off: problem = %q, want it to say the check could not be made", got)
	}

	if got := targetProblem(free, "target.test", 5*time.Second); !strings.Contains(got, "не удалось проверить") {
		t.Errorf("nothing listening: problem = %q, want it to say the check could not be made", got)
	}
}

func TestTargetWarnings(t *testing.T) {
	for name, want := range map[string]bool{
		"www.example.org":   false,
		"vpn.example.org":   true,
		"www.microsoft.com": true,
		"203.0.113.10":      true,
	} {
		if got := len(targetWarnings(name)) > 0; got != want {
			t.Errorf("%s: warned = %v, want %v", name, got, want)
		}
	}
}

func TestInstallScript(t *testing.T) {
	st := testState(t)
	nl := st.node("nl1")
	script, err := installScript(st, nl)
	if err != nil {
		t.Fatal(err)
	}
	s := string(script)

	// The embedded config is exactly the server config, and is valid JSON.
	const open, end = "<<'OBHOD_CONFIG_EOF'\n", "\nOBHOD_CONFIG_EOF\n"
	i, j := strings.Index(s, open), strings.Index(s, end)
	if i < 0 || j < i {
		t.Fatal("config heredoc not found")
	}
	var got, want map[string]any
	if err := json.Unmarshal([]byte(s[i+len(open):j]), &got); err != nil {
		t.Fatalf("embedded config: %v", err)
	}
	want = roundTrip(t, serverConfig(st, nl))
	a, _ := json.Marshal(got)
	b, _ := json.Marshal(want)
	if string(a) != string(b) {
		t.Error("embedded config differs from serverConfig")
	}

	for _, must := range []string{
		"XRAY_VERSION='" + defaultXrayVersion + "'",
		"TCP_PORTS='443 8443'",
		"UDP_PORTS='443'",
		"run -test -config", // a bad config must never reach the running service
		"set -euo pipefail",
	} {
		if !strings.Contains(s, must) {
			t.Errorf("installer lacks %q", must)
		}
	}
	if strings.Contains(s, "{{") {
		t.Error("unrendered template action left in the installer")
	}

	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	path := filepath.Join(t.TempDir(), "install.sh")
	if err := os.WriteFile(path, script, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bash, "-n", path).CombinedOutput(); err != nil {
		t.Errorf("bash -n: %v\n%s", err, out)
	}
}

// proxy.txt is where a person looks up what to type into a browser, so it has
// to name the address and the password the configs really listen with.
func TestRenderWritesLocalProxyAddresses(t *testing.T) {
	dir := t.TempDir()
	if _, err := render(testState(t), dir); err != nil {
		t.Fatal(err)
	}
	client := filepath.Join(dir, "clients", "anna")
	txt, err := os.ReadFile(filepath.Join(client, "proxy.txt"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(client, "xray", "fi1-vision.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	lines := strings.Fields(string(txt))
	if len(lines) != 2 {
		t.Fatalf("proxy.txt has %d lines, want socks and http:\n%s", len(lines), txt)
	}
	// socks5h, not socks5: the name is resolved by the tunnel, not the local network.
	for i, want := range []struct{ scheme, inbound string }{{"socks5h", "socks"}, {"http", "http"}} {
		u, err := url.Parse(lines[i])
		if err != nil {
			t.Fatal(err)
		}
		in := find(t, cfg["inbounds"], want.inbound)
		account := dig(t, in, "settings", "accounts").([]any)[0].(map[string]any)
		pass, _ := u.User.Password()
		if u.Scheme != want.scheme || u.Host != fmt.Sprintf("127.0.0.1:%v", in["port"]) ||
			u.User.Username() != account["user"] || pass != account["pass"] {
			t.Errorf("proxy.txt says %s, the config listens on port %v as %v", lines[i], in["port"], account)
		}
	}
}

// A folder handed to a person must not carry profiles of a removed node or a
// revoked user from an earlier render.
func TestRenderDropsRemovedNodesAndUsers(t *testing.T) {
	st := testState(t)
	dir := t.TempDir()
	if _, err := render(st, dir); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "package.zip")
	if err := os.WriteFile(other, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	st.Nodes = []*Node{st.node("nl1"), st.node("ru1")}
	st.Users = st.Users[:1]
	if _, err := render(st, dir); err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{"nodes/fi1", "clients/anna", "clients/me/xray/fi1-vision.json"} {
		if _, err := os.Stat(filepath.Join(dir, gone)); !os.IsNotExist(err) {
			t.Errorf("%s still there after render", gone)
		}
	}
	if _, err := os.Stat(other); err != nil {
		t.Errorf("render removed a file it does not own: %v", err)
	}
}

func TestRenderWritesPrivateFiles(t *testing.T) {
	st := testState(t)
	dir := t.TempDir()
	files, err := render(st, dir)
	if err != nil {
		t.Fatal(err)
	}
	// 3 installers; per user: 8 pinned configs, links, subscription, auto,
	// the phone config, local proxy addresses.
	if want := 3 + 2*(8+5); len(files) != want {
		t.Errorf("rendered %d files, want %d", len(files), want)
	}
	for _, f := range files {
		fi, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %o, want 600", f, fi.Mode().Perm())
		}
		if strings.HasSuffix(f, ".json") {
			b, _ := os.ReadFile(f)
			if !json.Valid(b) {
				t.Errorf("%s is not valid JSON", f)
			}
		}
	}
}
