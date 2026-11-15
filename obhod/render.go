package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
)

//go:embed install.sh.tmpl
var installTmpl string

func marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func joinPorts(ports ...int) string {
	var s []string
	for _, p := range ports {
		if p != 0 {
			s = append(s, strconv.Itoa(p))
		}
	}
	return strings.Join(s, " ")
}

// installScript renders the self-contained installer for one node.
func installScript(st *State, n *Node) ([]byte, error) {
	cfg, err := marshal(serverConfig(st, n))
	if err != nil {
		return nil, err
	}
	t, err := template.New("install").Parse(installTmpl)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	err = t.Execute(&buf, map[string]string{
		"Node":        n.Name,
		"XrayVersion": st.XrayVersion,
		"TCPPorts":    joinPorts(n.XHTTP.Port, n.Vision.Port),
		"UDPPorts":    joinPorts(n.Hy2.Port),
		"Config":      strings.TrimRight(string(cfg), "\n"),
	})
	return buf.Bytes(), err
}

// render writes everything under dir:
//
//	nodes/<node>/install.sh          run on the server
//	clients/<user>/links.txt         share links, one per line
//	clients/<user>/sub.txt           the same links as a base64 subscription
//	clients/<user>/xray/auto.json    desktop config with failover (2+ XHTTP profiles)
//	clients/<user>/xray/<tag>.json   desktop config pinned to one profile
func render(st *State, dir string) ([]string, error) {
	if len(st.Nodes) == 0 {
		return nil, fmt.Errorf("no nodes: add one with `obhod node add`")
	}
	if len(st.Users) == 0 {
		return nil, fmt.Errorf("no users: add one with `obhod user add`")
	}
	var written []string
	write := func(rel string, data []byte) error {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return err
		}
		// Everything rendered carries credentials.
		if err := os.WriteFile(p, data, 0o600); err != nil {
			return err
		}
		written = append(written, p)
		return nil
	}

	for _, n := range st.Nodes {
		script, err := installScript(st, n)
		if err != nil {
			return nil, err
		}
		if err := write(filepath.Join("nodes", n.Name, "install.sh"), script); err != nil {
			return nil, err
		}
	}

	for _, u := range st.Users {
		ps := profiles(st, u)
		base := filepath.Join("clients", u.Name)
		var links strings.Builder
		for _, p := range ps {
			links.WriteString(p.Link)
			links.WriteByte('\n')
			cfg, err := marshal(singleClient(p))
			if err != nil {
				return nil, err
			}
			if err := write(filepath.Join(base, "xray", p.Tag+".json"), cfg); err != nil {
				return nil, err
			}
		}
		if err := write(filepath.Join(base, "links.txt"), []byte(links.String())); err != nil {
			return nil, err
		}
		if err := write(filepath.Join(base, "sub.txt"), []byte(subscription(ps)+"\n")); err != nil {
			return nil, err
		}
		if auto := autoClient(ps); auto != nil {
			cfg, err := marshal(auto)
			if err != nil {
				return nil, err
			}
			if err := write(filepath.Join(base, "xray", "auto.json"), cfg); err != nil {
				return nil, err
			}
		}
	}
	return written, nil
}
