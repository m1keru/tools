package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type obj = map[string]any

const visionFlow = "xtls-rprx-vision"

// Transport kinds, in order of preference.
const (
	kindXHTTP  = "xhttp"
	kindVision = "vision"
	kindHy2    = "hy2"
)

// Russian destinations are routed around the tunnel: it keeps the volume sent
// to the exit low, keeps Russian services from learning the exit address, and
// keeps sites that refuse foreign addresses working.
var ruDomains = []string{"geosite:category-ru", "domain:ru", "domain:su", "domain:xn--p1ai"}

// xmux keeps XHTTP on at most two long-lived TLS connections. TSPU freezes a
// client that opens more than three TLS handshakes to one SNI within a minute,
// so the number of connections is a safety property, not a tuning knob. Every
// field is spelled out because Xray drops its defaults once any one is set.
func xmux() obj {
	return obj{
		"maxConnections":   2,
		"cMaxReuseTimes":   0,
		"hMaxRequestTimes": "600-900",
		"hMaxReusableSecs": "1800-3000",
		"hKeepAlivePeriod": 0,
	}
}

func (n *Node) decryption() string { return "mlkem768x25519plus.native.600s." + n.XHTTP.EncPrivate }
func (n *Node) encryption() string { return "mlkem768x25519plus.native.0rtt." + n.XHTTP.EncPublic }

func realityClient(n *Node, fp string) obj {
	return obj{
		"serverName":  n.Reality.ServerName,
		"fingerprint": fp,
		"password":    n.Reality.PublicKey,
		"shortId":     n.Reality.ShortID,
	}
}

// xhttpOutbound is VLESS + XHTTP + REALITY with VLESS Encryption, which is
// what lets Vision padding run over a transport other than raw TCP.
func xhttpOutbound(tag string, n *Node, id, fp string) obj {
	return obj{
		"tag":      tag,
		"protocol": "vless",
		"settings": obj{
			"address":    n.Address,
			"port":       n.XHTTP.Port,
			"id":         id,
			"encryption": n.encryption(),
			"flow":       visionFlow,
		},
		"streamSettings": obj{
			"network": "xhttp",
			"xhttpSettings": obj{
				"path": n.XHTTP.Path,
				"mode": "stream-one",
				"xmux": xmux(),
			},
			"security":        "reality",
			"realitySettings": realityClient(n, fp),
		},
	}
}

func visionOutbound(tag string, n *Node, id, fp string) obj {
	return obj{
		"tag":      tag,
		"protocol": "vless",
		"settings": obj{
			"address":    n.Address,
			"port":       n.Vision.Port,
			"id":         id,
			"encryption": "none",
			"flow":       visionFlow,
		},
		"streamSettings": obj{
			"network":         "raw",
			"security":        "reality",
			"realitySettings": realityClient(n, fp),
		},
	}
}

func hy2Outbound(tag string, n *Node, auth string) obj {
	return obj{
		"tag":      tag,
		"protocol": "hysteria",
		"settings": obj{"version": 2, "address": n.Address, "port": n.Hy2.Port},
		"streamSettings": obj{
			"network":          "hysteria",
			"hysteriaSettings": obj{"version": 2, "auth": auth},
			"security":         "tls",
			"tlsSettings": obj{
				"serverName":           n.Reality.ServerName,
				"alpn":                 []string{"h3"},
				"pinnedPeerCertSha256": n.Hy2.CertSHA256,
			},
			"finalmask": obj{
				"udp": []any{obj{"type": "salamander", "settings": obj{"password": n.Hy2.ObfsPassword}}},
			},
		},
	}
}

// profile is one way for one user to reach one node.
type profile struct {
	Tag      string
	Kind     string
	Node     *Node
	User     *User
	Outbound obj
	Link     string
}

// profiles lists a user's profiles: exits first, then relays, and within a
// node the transports in order of preference.
func profiles(st *State, u *User) []profile {
	var out []profile
	add := func(relays bool) {
		for _, n := range st.Nodes {
			if n.IsRelay() != relays {
				continue
			}
			if n.XHTTP.Port != 0 {
				tag := n.Name + "-" + kindXHTTP
				out = append(out, profile{tag, kindXHTTP, n, u, xhttpOutbound(tag, n, u.UUID, st.Fingerprint), xhttpLink(tag, n, u, st.Fingerprint)})
			}
			if n.Vision.Port != 0 {
				tag := n.Name + "-" + kindVision
				out = append(out, profile{tag, kindVision, n, u, visionOutbound(tag, n, u.UUID, st.Fingerprint), visionLink(tag, n, u, st.Fingerprint)})
			}
			if n.Hy2.Port != 0 {
				tag := n.Name + "-" + kindHy2
				out = append(out, profile{tag, kindHy2, n, u, hy2Outbound(tag, n, u.Hy2Auth), hy2Link(tag, n, u)})
			}
		}
	}
	add(false)
	add(true)
	return out
}

func hostPort(host string, port int) string { return net.JoinHostPort(host, strconv.Itoa(port)) }

// query builds a URL query with a fixed key order, so rendered links are
// stable between runs and reviewable in a diff.
func query(kv ...string) string {
	var b strings.Builder
	for i := 0; i+1 < len(kv); i += 2 {
		if b.Len() > 0 {
			b.WriteByte('&')
		}
		b.WriteString(kv[i])
		b.WriteByte('=')
		b.WriteString(url.QueryEscape(kv[i+1]))
	}
	return b.String()
}

func realityQuery(n *Node, fp string) []string {
	return []string{"security", "reality", "sni", n.Reality.ServerName, "fp", fp, "pbk", n.Reality.PublicKey, "sid", n.Reality.ShortID}
}

func xhttpLink(name string, n *Node, u *User, fp string) string {
	extra, _ := json.Marshal(obj{"xmux": xmux()})
	kv := []string{"encryption", n.encryption(), "flow", visionFlow}
	kv = append(kv, realityQuery(n, fp)...)
	kv = append(kv, "type", "xhttp", "path", n.XHTTP.Path, "mode", "stream-one", "extra", string(extra))
	return fmt.Sprintf("vless://%s@%s?%s#%s", u.UUID, hostPort(n.Address, n.XHTTP.Port), query(kv...), url.PathEscape(name))
}

func visionLink(name string, n *Node, u *User, fp string) string {
	kv := []string{"encryption", "none", "flow", visionFlow}
	kv = append(kv, realityQuery(n, fp)...)
	kv = append(kv, "type", "tcp", "headerType", "none")
	return fmt.Sprintf("vless://%s@%s?%s#%s", u.UUID, hostPort(n.Address, n.Vision.Port), query(kv...), url.PathEscape(name))
}

func hy2Link(name string, n *Node, u *User) string {
	// The certificate is self-signed, so clients that ignore pinSHA256 need
	// insecure=1 to connect at all; clients that honour the pin still verify.
	kv := []string{"sni", n.Reality.ServerName, "obfs", "salamander", "obfs-password", n.Hy2.ObfsPassword,
		"pinSHA256", n.Hy2.CertSHA256, "insecure", "1"}
	return fmt.Sprintf("hysteria2://%s@%s/?%s#%s", url.PathEscape(u.Hy2Auth), hostPort(n.Address, n.Hy2.Port), query(kv...), url.PathEscape(name))
}

// subscription is the base64 list of links that client apps import by URL.
func subscription(ps []profile) string {
	links := make([]string, len(ps))
	for i, p := range ps {
		links[i] = p.Link
	}
	return base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n") + "\n"))
}

// localProxy is where the user's desktop configs listen. Any program on the
// machine can connect to 127.0.0.1, and through an open proxy on Xray's stock
// port it learns the exit address in one request. So the proxy asks for a
// password, and both it and the ports come from the user's secret: they stay
// the same between renders and need no field in the state. The ports sit
// below the ranges operating systems hand out for outgoing connections.
//
// shortcut: the port cannot be chosen, give User a field for it when one
// clashes with a service already listening on somebody's machine.
func (u *User) localProxy() (pass string, socksPort, httpPort int) {
	sum := sha256.Sum256([]byte("obhod local proxy\n" + u.UUID))
	port := 20000 + int(binary.BigEndian.Uint16(sum[:2]))%12000
	return hex.EncodeToString(sum[2:14]), port, port + 1
}

func localInbounds(u *User) []any {
	sniff := obj{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true}
	pass, socksPort, httpPort := u.localProxy()
	accounts := []any{obj{"user": u.Name, "pass": pass}}
	return []any{
		obj{"tag": "socks", "listen": "127.0.0.1", "port": socksPort, "protocol": "socks",
			"settings": obj{"auth": "password", "accounts": accounts, "udp": true}, "sniffing": sniff},
		obj{"tag": "http", "listen": "127.0.0.1", "port": httpPort, "protocol": "http",
			"settings": obj{"accounts": accounts}, "sniffing": sniff},
	}
}

// splitRules sends local and Russian destinations direct; whatever is left
// falls through to the rule the caller appends.
func splitRules() []any {
	return []any{
		obj{"ip": []string{"geoip:private"}, "outboundTag": "direct"},
		obj{"domain": ruDomains, "outboundTag": "direct"},
		obj{"ip": []string{"geoip:ru"}, "outboundTag": "direct"},
		obj{"protocol": []string{"bittorrent"}, "outboundTag": "direct"},
	}
}

func baseClient(u *User, proxies []any, rules []any) obj {
	outbounds := append(append([]any{}, proxies...),
		obj{"tag": "direct", "protocol": "freedom"},
		obj{"tag": "block", "protocol": "blackhole"})
	return obj{
		"log":       obj{"loglevel": "warning"},
		"inbounds":  localInbounds(u),
		"outbounds": outbounds,
		"routing":   obj{"domainStrategy": "AsIs", "rules": rules},
	}
}

// singleClient is a config that uses exactly one profile. These are the
// manual fallbacks: nothing probes them in the background.
//
// Russian destinations go direct: a Russian service reached through a node
// learns the node's address, and for a relay that is the very address clients
// connect to. A relay with AllowRU is the exception. It is for networks where
// only whitelisted addresses answer and direct connections fail, so it takes
// everything and serves Russian destinations itself.
func singleClient(p profile) obj {
	rules := splitRules()
	if p.Node.IsRelay() && p.Node.AllowRU {
		rules = []any{obj{"ip": []string{"geoip:private"}, "outboundTag": "direct"}}
	}
	rules = append(rules, obj{"network": "tcp,udp", "outboundTag": p.Tag})
	return baseClient(p.User, []any{p.Outbound}, rules)
}

// mobileClient is autoClient for a phone: the same nodes, health checks and
// routing, and nothing listening. The app brings the tunnel interface itself
// (v2rayNG adds a tun inbound to a config it imports), and a local proxy port
// on a phone would only help other apps find the tunnel.
func mobileClient(ps []profile) obj {
	c := autoClient(ps)
	if c != nil {
		c["inbounds"] = []any{}
	}
	return c
}

// autoProfiles picks the profiles that are safe to health-check in the
// background: XHTTP only. Its probes ride the existing multiplexed connection
// and cost no TLS handshake. Vision opens a handshake per connection, which
// the burst rule punishes, and on some operators a single UDP packet to a
// watched address blocks that address for minutes, so neither is probed
// automatically.
func autoProfiles(ps []profile) []profile {
	var out []profile
	for _, p := range ps {
		if p.Kind == kindXHTTP {
			out = append(out, p)
		}
	}
	return out
}

// autoClient fails over between XHTTP profiles. leastLoad ranks live
// candidates by latency jitter scaled by sqrt(cost), so with costs a factor
// of 100 apart the first exit is used unless it is dead or ten times less
// steady than the next one, and a relay is used only when no exit answers,
// which is what a whitelist-only network looks like. It returns nil when
// there is nothing to fail over between.
func autoClient(ps []profile) obj {
	auto := autoProfiles(ps)
	if len(auto) < 2 {
		return nil
	}
	var proxies, costs []any
	var tags []string
	exitCost, relayCost := 1.0, 1e8
	for _, p := range auto {
		proxies = append(proxies, p.Outbound)
		tags = append(tags, p.Tag)
		cost := exitCost
		if p.Node.IsRelay() {
			cost = relayCost
			relayCost *= 100
		} else {
			exitCost *= 100
		}
		costs = append(costs, obj{"match": p.Tag, "value": cost})
	}
	rules := append(splitRules(), obj{"network": "tcp,udp", "balancerTag": "auto"})
	c := baseClient(auto[0].User, proxies, rules)
	balancer, checks := failover("auto", tags, costs)
	c["routing"].(obj)["balancers"] = []any{balancer}
	c["burstObservatory"] = checks
	return c
}

// failover builds a balancer that keeps traffic on the cheapest outbound that
// answers, and the health checks it decides by. Clients use it to pick a node
// and relays to pick an exit, so both leave a dead one by the same rule.
func failover(tag string, tags []string, costs []any) (balancer, checks obj) {
	balancer = obj{
		"tag":         tag,
		"selector":    tags,
		"fallbackTag": tags[0],
		// Xray drops a node on its own only when every kept check has failed.
		// The tolerance takes it out once more than half of them have: two of
		// the three kept. One failure leaves it in, even with only two
		// results on record: the first check through a fresh XHTTP connection
		// is slow and now and then times out on a healthy node, and a single
		// lost check must not move a user to another exit address.
		"strategy": obj{"type": "leastLoad", "settings": obj{"expected": 1, "costs": costs, "tolerance": 0.5}},
	}
	// Each node is checked `sampling` times, at random moments, in every
	// window of interval × sampling. Two checks a minute notice a dead node in
	// a minute or two and keep a dead node's handshakes under the burst rule.
	checks = obj{
		"subjectSelector": tags,
		"pingConfig": obj{
			"destination": "https://www.gstatic.com/generate_204",
			"interval":    "30s",
			"sampling":    3,
			"timeout":     "10s",
		},
	}
	return balancer, checks
}
