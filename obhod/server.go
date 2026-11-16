package main

import "strings"

func realityServer(n *Node) obj {
	return obj{
		"target":      n.Reality.Target,
		"serverNames": []string{n.Reality.ServerName},
		"privateKey":  n.Reality.PrivateKey,
		"shortIds":    []string{n.Reality.ShortID},
	}
}

func pemLines(s string) []string {
	return strings.Split(strings.TrimSpace(s), "\n")
}

// serverConfig builds the Xray config for one node.
//
// A node refuses Russian destinations unless AllowRU is set: clients already
// route those direct, and a node that never touches Russian services cannot be
// found in their logs.
//
// An exit sends the rest to the internet. A relay forwards it to its exit over
// XHTTP, under an identity of its own so it can be revoked alone. A relay with
// AllowRU serves Russian destinations itself, from the address its clients
// connect to: that is for networks where only whitelisted addresses answer.
func serverConfig(st *State, n *Node) obj {
	sniff := obj{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true}
	var inbounds []any

	if n.XHTTP.Port != 0 {
		var users []any
		for _, u := range st.Users {
			users = append(users, obj{"id": u.UUID, "email": u.Name + "@" + kindXHTTP, "flow": visionFlow})
		}
		for _, r := range st.relaysOf(n.Name) {
			users = append(users, obj{"id": r.LinkUUID, "email": "relay-" + r.Name + "@" + kindXHTTP, "flow": visionFlow})
		}
		inbounds = append(inbounds, obj{
			"tag":      kindXHTTP,
			"port":     n.XHTTP.Port,
			"protocol": "vless",
			"settings": obj{"users": users, "decryption": n.decryption()},
			"streamSettings": obj{
				"network":         "xhttp",
				"xhttpSettings":   obj{"path": n.XHTTP.Path, "mode": "auto"},
				"security":        "reality",
				"realitySettings": realityServer(n),
			},
			"sniffing": sniff,
		})
	}

	if n.Vision.Port != 0 {
		var users []any
		for _, u := range st.Users {
			users = append(users, obj{"id": u.UUID, "email": u.Name + "@" + kindVision, "flow": visionFlow})
		}
		inbounds = append(inbounds, obj{
			"tag":      kindVision,
			"port":     n.Vision.Port,
			"protocol": "vless",
			"settings": obj{"users": users, "decryption": "none"},
			"streamSettings": obj{
				"network":         "raw",
				"security":        "reality",
				"realitySettings": realityServer(n),
			},
			"sniffing": sniff,
		})
	}

	if n.Hy2.Port != 0 {
		var users []any
		for _, u := range st.Users {
			users = append(users, obj{"auth": u.Hy2Auth, "email": u.Name + "@" + kindHy2})
		}
		inbounds = append(inbounds, obj{
			"tag":      kindHy2,
			"port":     n.Hy2.Port,
			"protocol": "hysteria",
			"settings": obj{"version": 2, "users": users},
			"streamSettings": obj{
				"network":          "hysteria",
				"hysteriaSettings": obj{"version": 2},
				"security":         "tls",
				"tlsSettings": obj{
					"alpn":         []string{"h3"},
					"certificates": []any{obj{"certificate": pemLines(n.Hy2.CertPEM), "key": pemLines(n.Hy2.KeyPEM)}},
				},
				"finalmask": obj{
					"udp": []any{obj{"type": "salamander", "settings": obj{"password": n.Hy2.ObfsPassword}}},
				},
			},
			"sniffing": sniff,
		})
	}

	// Freedom refuses private and reserved addresses for traffic that arrived
	// over VLESS or Hysteria by default, so clients cannot reach the server's
	// own loopback or LAN through it.
	direct := obj{"tag": "direct", "protocol": "freedom"}
	block := obj{"tag": "block", "protocol": "blackhole"}
	// Port 25 is how a compromised client turns a node into a spam source and
	// gets its address onto mail blocklists; mail apps submit on 465 and 587.
	rules := []any{
		obj{"network": "tcp", "port": "25", "outboundTag": "block"},
		obj{"protocol": []string{"bittorrent"}, "outboundTag": "block"},
	}
	outbounds := []any{direct, block}
	if n.IsRelay() {
		up := st.node(n.Upstream)
		outbounds = []any{xhttpOutbound("upstream", up, n.LinkUUID, st.Fingerprint), direct, block}
	}
	switch {
	case !n.AllowRU:
		rules = append(rules,
			obj{"domain": ruDomains, "outboundTag": "block"},
			obj{"ip": []string{"geoip:ru"}, "outboundTag": "block"})
	case n.IsRelay():
		// Without this rule they would follow the default route to the exit.
		rules = append(rules,
			obj{"domain": ruDomains, "outboundTag": "direct"},
			obj{"ip": []string{"geoip:ru"}, "outboundTag": "direct"})
	}

	return obj{
		// No access log: the server keeps no record of who went where.
		"log":       obj{"loglevel": "warning", "access": "none"},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"routing":   obj{"domainStrategy": "AsIs", "rules": rules},
	}
}
