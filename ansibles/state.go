package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/m1keru/tools/ansibles/internal/keys"
)

const (
	stateVersion       = 1
	defaultXrayVersion = "v26.11.9"
	defaultFingerprint = "firefox"
)

// State is everything needed to rebuild every server and client config. It
// holds private keys, so it is written with mode 0600 and must stay out of git.
type State struct {
	Version     int     `json:"version"`
	XrayVersion string  `json:"xray_version"`
	Fingerprint string  `json:"fingerprint"`
	Users       []*User `json:"users"`
	Nodes       []*Node `json:"nodes"`
}

type User struct {
	Name    string `json:"name"`
	UUID    string `json:"uuid"`
	Hy2Auth string `json:"hy2_auth"`
}

// Node is one server. With Upstream empty it is an exit: traffic leaves to the
// internet from it. With Upstream set it is a relay: an entry point that hands
// everything except Russian destinations to an exit. Upstream names one exit
// or several, comma-separated in order of preference; with several the relay
// keeps to the first one that answers.
type Node struct {
	Name     string  `json:"name"`
	Address  string  `json:"address"`
	Upstream string  `json:"upstream,omitempty"`
	LinkUUID string  `json:"link_uuid,omitempty"`
	AllowRU  bool    `json:"allow_ru,omitempty"`
	Reality  Reality `json:"reality"`
	XHTTP    XHTTP   `json:"xhttp"`
	Vision   Vision  `json:"vision"`
	Hy2      Hy2     `json:"hy2"`
}

type Reality struct {
	Target     string `json:"target"`
	ServerName string `json:"server_name"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	ShortID    string `json:"short_id"`
}

// XHTTP is VLESS over XHTTP over REALITY. A port of 0 disables a transport.
type XHTTP struct {
	Port       int    `json:"port"`
	Path       string `json:"path"`
	EncPrivate string `json:"enc_private"`
	EncPublic  string `json:"enc_public"`
}

type Vision struct {
	Port int `json:"port"`
}

type Hy2 struct {
	Port         int    `json:"port"`
	ObfsPassword string `json:"obfs_password"`
	CertPEM      string `json:"cert_pem"`
	KeyPEM       string `json:"key_pem"`
	CertSHA256   string `json:"cert_sha256"`
}

func (n *Node) IsRelay() bool { return n.Upstream != "" }

// upstreams lists the exits a relay forwards to, in order of preference.
func (n *Node) upstreams() []string {
	if n.Upstream == "" {
		return nil
	}
	return strings.Split(n.Upstream, ",")
}

// Names become outbound tags; Xray balancers match tags by prefix, so names
// are kept to plain alphanumerics to rule out one tag prefixing another.
var nameRe = regexp.MustCompile(`^[a-z0-9]{1,24}$`)

func validName(s string) error {
	if !nameRe.MatchString(s) {
		return fmt.Errorf("name %q: use 1-24 lowercase letters and digits", s)
	}
	return nil
}

func newState() *State {
	return &State{Version: stateVersion, XrayVersion: defaultXrayVersion, Fingerprint: defaultFingerprint}
}

func loadState(path string) (*State, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%s not found: run `ansibles init` first", path)
		}
		return nil, err
	}
	st := &State{}
	if err := json.Unmarshal(b, st); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if st.Version != stateVersion {
		return nil, fmt.Errorf("%s: unsupported state version %d", path, st.Version)
	}
	return st, st.validate()
}

func (st *State) save(path string) error {
	if err := st.validate(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (st *State) node(name string) *Node {
	for _, n := range st.Nodes {
		if n.Name == name {
			return n
		}
	}
	return nil
}

func (st *State) user(name string) *User {
	for _, u := range st.Users {
		if u.Name == name {
			return u
		}
	}
	return nil
}

// relaysOf lists the relays that forward into the given exit.
func (st *State) relaysOf(exit string) []*Node {
	var out []*Node
	for _, n := range st.Nodes {
		for _, up := range n.upstreams() {
			if up == exit {
				out = append(out, n)
			}
		}
	}
	return out
}

func (st *State) validate() error {
	seen := map[string]bool{}
	for _, u := range st.Users {
		if err := validName(u.Name); err != nil {
			return fmt.Errorf("user: %w", err)
		}
		if seen["u:"+u.Name] {
			return fmt.Errorf("duplicate user %q", u.Name)
		}
		seen["u:"+u.Name] = true
	}
	for _, n := range st.Nodes {
		if err := validName(n.Name); err != nil {
			return fmt.Errorf("node: %w", err)
		}
		if seen["n:"+n.Name] {
			return fmt.Errorf("duplicate node %q", n.Name)
		}
		seen["n:"+n.Name] = true
		if n.Address == "" {
			return fmt.Errorf("node %s: address is empty", n.Name)
		}
		if _, _, err := net.SplitHostPort(n.Reality.Target); err != nil {
			return fmt.Errorf("node %s: reality target %q must be host:port", n.Name, n.Reality.Target)
		}
		if n.XHTTP.Port == 0 && n.Vision.Port == 0 && n.Hy2.Port == 0 {
			return fmt.Errorf("node %s: every transport is disabled", n.Name)
		}
		if n.XHTTP.Port != 0 && n.XHTTP.Port == n.Vision.Port {
			return fmt.Errorf("node %s: xhttp and vision cannot share TCP port %d", n.Name, n.XHTTP.Port)
		}
		for _, p := range []int{n.XHTTP.Port, n.Vision.Port, n.Hy2.Port} {
			if p < 0 || p > 65535 {
				return fmt.Errorf("node %s: port %d out of range", n.Name, p)
			}
		}
	}
	for _, n := range st.Nodes {
		listed := map[string]bool{}
		for _, name := range n.upstreams() {
			up := st.node(name)
			switch {
			case up == nil:
				return fmt.Errorf("relay %s: upstream %q does not exist", n.Name, name)
			case up.IsRelay():
				return fmt.Errorf("relay %s: upstream %q is itself a relay; chain relays to an exit", n.Name, name)
			case up.XHTTP.Port == 0:
				return fmt.Errorf("relay %s: upstream %q has xhttp disabled, and the relay link uses it", n.Name, name)
			case listed[name]:
				return fmt.Errorf("relay %s: upstream %q is listed twice", n.Name, name)
			}
			listed[name] = true
		}
	}
	return nil
}

func newUser(name string) (*User, error) {
	if err := validName(name); err != nil {
		return nil, err
	}
	id, err := keys.NewUUID()
	if err != nil {
		return nil, err
	}
	auth, err := keys.RandToken(24)
	if err != nil {
		return nil, err
	}
	return &User{Name: name, UUID: id, Hy2Auth: auth}, nil
}

type nodeOpts struct {
	Name, Address, Target, ServerName, Upstream string
	XHTTPPort, VisionPort, Hy2Port              int
	AllowRU                                     bool
}

func newNode(o nodeOpts) (*Node, error) {
	if err := validName(o.Name); err != nil {
		return nil, err
	}
	host, _, err := net.SplitHostPort(o.Target)
	if err != nil {
		return nil, fmt.Errorf("target %q must be host:port, for example www.example.com:443", o.Target)
	}
	if o.ServerName == "" {
		o.ServerName = host
	}
	n := &Node{
		Name:     o.Name,
		Address:  o.Address,
		Upstream: o.Upstream,
		AllowRU:  o.AllowRU,
		Reality:  Reality{Target: o.Target, ServerName: o.ServerName},
		XHTTP:    XHTTP{Port: o.XHTTPPort},
		Vision:   Vision{Port: o.VisionPort},
		Hy2:      Hy2{Port: o.Hy2Port},
	}
	if n.IsRelay() {
		if n.LinkUUID, err = keys.NewUUID(); err != nil {
			return nil, err
		}
	}
	return n, n.rekey()
}

// rekey replaces every secret of the node. Use it after an address was burned
// together with its keys, or when a client config may have leaked.
func (n *Node) rekey() error {
	var err error
	if n.Reality.PrivateKey, n.Reality.PublicKey, err = keys.NewX25519(); err != nil {
		return err
	}
	if n.Reality.ShortID, err = keys.RandHex(8); err != nil {
		return err
	}
	if n.XHTTP.EncPrivate, n.XHTTP.EncPublic, err = keys.NewX25519(); err != nil {
		return err
	}
	p, err := keys.RandHex(12)
	if err != nil {
		return err
	}
	n.XHTTP.Path = "/" + p
	if n.Hy2.ObfsPassword, err = keys.RandToken(24); err != nil {
		return err
	}
	n.Hy2.CertPEM, n.Hy2.KeyPEM, n.Hy2.CertSHA256, err = keys.NewSelfSignedCert(n.Reality.ServerName)
	return err
}

// Names the censor is known to pattern-match in SNI, and targets that draw
// attention because every tutorial uses them.
var (
	sniTells   = []string{"vpn", "proxy", "node", "xray", "reality", "vless", "tunnel"}
	sniCrowded = []string{"google", "microsoft", "apple", "cloudflare", "amazon"}
)

// targetWarnings flags REALITY targets that are likely to be a liability.
func targetWarnings(serverName string) []string {
	var w []string
	s := strings.ToLower(serverName)
	for _, t := range sniTells {
		if strings.Contains(s, t) {
			w = append(w, fmt.Sprintf("в имени сервера есть %q: по SNI это читается как туннель", t))
		}
	}
	for _, t := range sniCrowded {
		if strings.Contains(s, t) {
			w = append(w, fmt.Sprintf("имя сервера похоже на %s: ваш адрес не в их сети, несоответствие легко заметить; "+
				"берите сайт из той же ASN, что и сервер", t))
		}
	}
	if net.ParseIP(serverName) != nil {
		w = append(w, "имя сервера задано IP-адресом; REALITY нужно имя настоящего сайта с TLS 1.3")
	}
	return w
}
