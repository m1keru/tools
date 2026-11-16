package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// fakeHost describes a server to the installer through stand-in commands, so
// its read-only preflight can be run against hosts we do not have: an old
// kernel, a busy port, a host without systemd.
type fakeHost struct {
	kernel  string // uname -r
	arch    string // uname -m
	systemd string // systemd version; empty means another init system
	sysv    bool   // sysvinit with start-stop-daemon and update-rc.d (Debian family)
	noInitd bool   // those tools are installed, but there is no /etc/init.d (a container)
	tcpBusy []int  // ports something already listens on
	udpBusy []int
	missing []string // tools that are not installed
	running bool     // the node's own service is already up
	freeKB  int
	// What `iptables -S INPUT` prints, one rule per line; empty means the
	// host has no iptables at all.
	iptables string
	// What `iptables -S OBHOD` prints: the chain an earlier run of the
	// installer left. Empty means there is no such chain.
	obhodChain string
	ufw        bool // ufw is installed and active
}

func modernHost() fakeHost {
	return fakeHost{kernel: "6.1.0-18-amd64", arch: "x86_64", systemd: "252", freeKB: 5 << 20}
}

// preflight runs `install.sh --check` for the node on the fake host and
// returns its output and whether it passed.
func preflight(t *testing.T, st *State, n *Node, h fakeHost, args ...string) (string, bool) {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	script, err := installScript(st, n)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "install.sh")
	if err := os.WriteFile(scriptPath, script, 0o600); err != nil {
		t.Fatal(err)
	}

	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	fake := func(name, body string) {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// The text tools are the real ones; everything that describes the host
	// is a stand-in. PATH holds nothing else, so the host's real state
	// cannot leak into the result.
	for _, tool := range []string{"awk", "grep"} {
		real, err := exec.LookPath(tool)
		if err != nil {
			t.Skipf("%s not available", tool)
		}
		if err := os.Symlink(real, filepath.Join(bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	fake("id", `if [ "$1" = -u ]; then echo 0; else exit 1; fi`)
	fake("uname", fmt.Sprintf(`case "$1" in -r) echo %s ;; -m) echo %s ;; esac`, h.kernel, h.arch))
	fake("df", fmt.Sprintf(`echo "Filesystem 1024-blocks Used Available Capacity Mounted on"; echo "/dev/vda1 99999999 1 %d 1%% /"`, h.freeKB))

	listen := func(ports []int, state string) string {
		var b strings.Builder
		for _, p := range ports {
			fmt.Fprintf(&b, "echo '%s 0 128 0.0.0.0:%d 0.0.0.0:*'; ", state, p)
		}
		return b.String()
	}
	fake("ss", fmt.Sprintf(`echo "State Recv-Q Send-Q Local Address:Port Peer Address:Port"
case "$1" in -ltn) %s ;; -lun) %s ;; esac`, listen(h.tcpBusy, "LISTEN")+":", listen(h.udpBusy, "UNCONN")+":"))

	env := []string{"PATH=" + bin}
	if h.systemd != "" {
		active := "exit 3"
		if h.running {
			active = "exit 0"
		}
		fake("systemctl", fmt.Sprintf(`case "$1" in --version) echo "systemd %s (%s-1)" ;; is-active) %s ;; esac`, h.systemd, h.systemd, active))
		env = append(env, "OBHOD_SYSTEMD_DIR="+dir)
	} else {
		env = append(env, "OBHOD_SYSTEMD_DIR="+filepath.Join(dir, "absent"))
		if h.sysv {
			fake("start-stop-daemon", "exit 0")
			fake("update-rc.d", "exit 0")
			initd := filepath.Join(dir, "init.d")
			if !h.noInitd {
				if err := os.Mkdir(initd, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if h.running {
				if err := os.WriteFile(filepath.Join(initd, "obhod-xray"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			env = append(env, "OBHOD_INITD_DIR="+initd)
		}
	}
	if h.iptables != "" {
		quote := func(rules string) string {
			var b strings.Builder
			for _, rule := range strings.Split(strings.TrimSpace(rules), "\n") {
				fmt.Fprintf(&b, " '%s'", strings.TrimSpace(rule))
			}
			return b.String()
		}
		// Asking for a chain that does not exist fails, as it does on a host
		// where the node never opened anything.
		chain := "exit 1"
		if h.obhodChain != "" {
			chain = "printf '%s\\n'" + quote(h.obhodChain)
		}
		fake("iptables", fmt.Sprintf(`case "$1 $2" in "-S INPUT") printf '%%s\n'%s ;; "-S OBHOD") %s ;; *) exit 1 ;; esac`, quote(h.iptables), chain))
	}
	if h.ufw {
		fake("ufw", `echo "Status: active"`)
	}
	absent := map[string]bool{}
	for _, m := range h.missing {
		absent[m] = true
	}
	for _, tool := range []string{"curl", "unzip", "sha256sum"} {
		if !absent[tool] {
			fake(tool, "exit 0")
		}
	}

	cmd := exec.Command(bash, append([]string{scriptPath, "--check"}, args...)...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return string(out), err == nil
}

// highPortNode is how a node looks on a host whose 443 belongs to something
// else: both TCP transports above 1024, no UDP.
func highPortNode(t *testing.T) (*State, *Node) {
	t.Helper()
	st := testState(t)
	n := st.node("fi1")
	n.XHTTP.Port, n.Vision.Port, n.Hy2.Port = 8443, 9443, 0
	return st, n
}

func TestPreflightPassesOnModernHost(t *testing.T) {
	st := testState(t)
	out, ok := preflight(t, st, st.node("nl1"), modernHost())
	if !ok || !strings.Contains(out, "preflight passed; nothing was changed") {
		t.Fatalf("ok=%v\n%s", ok, out)
	}
}

func TestPreflightRefusals(t *testing.T) {
	st := testState(t)
	nl := st.node("nl1")
	cases := []struct {
		name   string
		mutate func(*fakeHost)
		want   string
	}{
		{"kernel too old for the Go runtime", func(h *fakeHost) { h.kernel = "2.6.32-754.el6.x86_64" }, "kernel 2.6.32-754.el6.x86_64 is too old"},
		{"no init system we know", func(h *fakeHost) { h.systemd = "" }, "no supported init system"},
		{"tcp port taken", func(h *fakeHost) { h.tcpBusy = []int{80, 443} }, "TCP port 443 is already in use"},
		{"udp port taken", func(h *fakeHost) { h.udpBusy = []int{443} }, "UDP port 443 is already in use"},
		{"tool missing", func(h *fakeHost) { h.missing = []string{"unzip"} }, "missing tools: unzip"},
		{"disk full", func(h *fakeHost) { h.freeKB = 1024 }, "less than 150 MB free"},
		{"unknown cpu", func(h *fakeHost) { h.arch = "mips" }, "unsupported architecture mips"},
		// CentOS 7 era: no ambient capabilities, so no port below 1024 for
		// an unprivileged service.
		{"low port on old systemd", func(h *fakeHost) { h.systemd, h.kernel = "219", "3.10.0-1160.el7.x86_64" }, "move the node to ports above 1024"},
	}
	for _, c := range cases {
		h := modernHost()
		c.mutate(&h)
		out, ok := preflight(t, st, nl, h)
		if ok || !strings.Contains(out, c.want) {
			t.Errorf("%s: ok=%v, want refusal containing %q\n%s", c.name, ok, c.want, out)
		}
		if strings.Contains(out, "preflight passed") {
			t.Errorf("%s: reported a pass\n%s", c.name, out)
		}
	}
}

// Every problem is listed at once: nobody should have to fix a production
// host one error at a time.
func TestPreflightListsEveryProblem(t *testing.T) {
	st := testState(t)
	h := modernHost()
	h.tcpBusy, h.missing, h.freeKB = []int{443, 8443}, []string{"unzip", "curl"}, 1024
	out, ok := preflight(t, st, st.node("nl1"), h)
	if ok {
		t.Fatalf("passed:\n%s", out)
	}
	for _, want := range []string{"TCP port 443", "TCP port 8443", "missing tools: unzip curl", "150 MB"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestPreflightOldHostWithHighPorts(t *testing.T) {
	st, n := highPortNode(t)
	h := modernHost()
	h.systemd, h.kernel = "219", "3.10.0-1160.el7.x86_64"
	h.tcpBusy = []int{25, 80, 443, 993} // a mail and web host
	out, ok := preflight(t, st, n, h)
	if !ok {
		t.Fatalf("a node on high ports must fit beside existing services:\n%s", out)
	}
}

// oldDebian is a host from before systemd: sysvinit and a kernel without
// ambient capabilities. Xray itself runs there; only the service wrapper
// differs.
func oldDebian() fakeHost {
	return fakeHost{kernel: "3.2.0-4-amd64", arch: "x86_64", sysv: true, freeKB: 5 << 20}
}

func TestPreflightSysvinitHost(t *testing.T) {
	st, n := highPortNode(t)
	out, ok := preflight(t, st, n, oldDebian())
	if !ok || !strings.Contains(out, "sysvinit") || !strings.Contains(out, "preflight passed") {
		t.Fatalf("a sysvinit host must be accepted on high ports: ok=%v\n%s", ok, out)
	}

	// Nothing there can hand an unprivileged service a port below 1024.
	out, ok = preflight(t, st, st.node("nl1"), oldDebian())
	if ok || !strings.Contains(out, "move the node to ports above 1024") {
		t.Errorf("low ports on sysvinit: ok=%v\n%s", ok, out)
	}

	// An update of a running node keeps its own ports.
	h := oldDebian()
	h.running, h.tcpBusy = true, []int{8443, 9443}
	if out, ok := preflight(t, st, n, h); !ok {
		t.Errorf("update of a running sysvinit node refused:\n%s", out)
	}
	h.running = false
	if out, ok := preflight(t, st, n, h); ok || !strings.Contains(out, "TCP port 8443 is already in use") {
		t.Errorf("busy ports of a stopped node must be a conflict: ok=%v\n%s", ok, out)
	}

	// dpkg ships start-stop-daemon into containers that have no init at all:
	// say so in the preflight, not halfway through the install.
	h = oldDebian()
	h.noInitd = true
	if out, ok := preflight(t, st, n, h); ok || !strings.Contains(out, "no supported init system") {
		t.Errorf("a host without /etc/init.d must be refused: ok=%v\n%s", ok, out)
	}
}

// The sysvinit service must be as unprivileged as the systemd one and must
// come back after a reboot.
func TestSysvinitServiceShape(t *testing.T) {
	st := testState(t)
	script, err := installScript(st, st.node("nl1"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(script)
	for _, want := range []string{
		"### BEGIN INIT INFO",
		"# Default-Start:     2 3 4 5",
		`--chuid $SVC_USER`,
		`update-rc.d "$UNIT" defaults`,
		`update-rc.d -f "$UNIT" remove`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("installer lacks %q", want)
		}
	}
}

// Ports held by an earlier run of the same node are not a conflict.
func TestPreflightAllowsUpdatingRunningNode(t *testing.T) {
	st := testState(t)
	h := modernHost()
	h.running, h.tcpBusy, h.udpBusy = true, []int{443, 8443}, []int{443}
	if out, ok := preflight(t, st, st.node("nl1"), h); !ok {
		t.Fatalf("update refused:\n%s", out)
	}
}

// The rules of a host that closed a real node: everything arriving on eth0 is
// rejected unless a rule above lets it in. No firewall manager owns them, so
// the installer once reported a pass and left the node unreachable.
const closedByIptables = `
-P INPUT ACCEPT
-A INPUT -i eth0 -p icmp -m comment --comment "100 accept all icmp requests in INPUT for eth0" -j ACCEPT
-A INPUT -i eth0 -m state --state RELATED,ESTABLISHED -m comment --comment "101 accept related established" -j ACCEPT
-A INPUT -i eth0 -p tcp -m multiport --dports 22,5201,8301,8302 -m set --match-set wan_networks src -m comment --comment "300 allow tcp" -j ACCEPT
-A INPUT -i eth0 -m limit --limit 100/min -m comment --comment "998 log dropped packets in INPUT for eth0" -j NFLOG --nflog-group 1
-A INPUT -i eth0 -m comment --comment "999 reject all other packets in INPUT for eth0" -j REJECT --reject-with icmp-port-unreachable`

func TestPreflightSeesIptablesClosingPorts(t *testing.T) {
	st := testState(t)
	nl := st.node("nl1") // TCP 443 and 8443, UDP 443
	for _, c := range []struct{ name, rules, closed string }{
		{"everything else rejected on the public interface", closedByIptables, "tcp/443 tcp/8443 udp/443"},
		{"drop policy with one of the ports let in", `
-P INPUT DROP
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT`, "tcp/8443 udp/443"},
		{"a port range counts", `
-P INPUT DROP
-A INPUT -p tcp -m multiport --dports 22,400:9000 -j ACCEPT`, "udp/443"},
		// Loopback being open says nothing about the outside.
		{"loopback accepted, the rest dropped", `
-P INPUT ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -j DROP`, "tcp/443 tcp/8443 udp/443"},
		{"drop rules that single out an address or a state", `
-P INPUT ACCEPT
-A INPUT -s 203.0.113.9/32 -j DROP
-A INPUT -m conntrack --ctstate INVALID -j DROP
-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd`, ""},
		{"accept-all placed above the drop", `
-P INPUT DROP
-A INPUT -j ACCEPT
-A INPUT -j DROP`, ""},
	} {
		h := modernHost()
		h.iptables = c.rules
		out, ok := preflight(t, st, nl, h)
		if !ok {
			t.Errorf("%s: closed ports are a warning, not a refusal:\n%s", c.name, out)
		}
		warned := strings.Contains(out, "iptables rules close")
		if c.closed == "" && warned {
			t.Errorf("%s: warned about ports nothing closes:\n%s", c.name, out)
		}
		if c.closed != "" && !strings.Contains(out, "iptables rules close "+c.closed+":") {
			t.Errorf("%s: want a warning that names %q:\n%s", c.name, c.closed, out)
		}
	}
}

// The node's own chain opens the ports only while INPUT still jumps to it. A
// tool that manages the host's rules may take the jump out and leave the
// chain, and the node is closed again.
func TestPreflightCountsOwnChainOnlyWithItsJump(t *testing.T) {
	st := testState(t)
	nl := st.node("nl1")
	const chain = `
-N OBHOD
-A OBHOD -s 192.0.2.44/32 -p tcp -m tcp --dport 443 -j ACCEPT
-A OBHOD -s 192.0.2.44/32 -p tcp -m tcp --dport 8443 -j ACCEPT
-A OBHOD -s 192.0.2.44/32 -p udp -m udp --dport 443 -j ACCEPT`

	h := modernHost()
	h.iptables = strings.Replace(closedByIptables, "-P INPUT ACCEPT", "-P INPUT ACCEPT\n-A INPUT -j OBHOD", 1)
	h.obhodChain = chain
	if out, _ := preflight(t, st, nl, h); strings.Contains(out, "iptables rules close") {
		t.Errorf("the node's chain is in place and lets the ports in:\n%s", out)
	}

	h.iptables = closedByIptables
	if out, _ := preflight(t, st, nl, h); !strings.Contains(out, "iptables rules close tcp/443 tcp/8443 udp/443:") {
		t.Errorf("the jump is gone, so the chain opens nothing:\n%s", out)
	}
}

// --open-firewall on such a host lets the ports through, and --from narrows
// that to the addresses that are meant to connect.
func TestPreflightOpenFirewallFrom(t *testing.T) {
	st := testState(t)
	nl := st.node("nl1")
	closed := modernHost()
	closed.iptables = closedByIptables

	out, ok := preflight(t, st, nl, closed, "--open-firewall", "--from", "192.0.2.44,198.51.100.0/24")
	if !ok || !strings.Contains(out, "would open the ports in iptables for 192.0.2.44 198.51.100.0/24") {
		t.Errorf("--from on a closed host: ok=%v\n%s", ok, out)
	}
	if strings.Contains(out, "or open them yourself") {
		t.Errorf("asked to open the ports and still told to do it by hand:\n%s", out)
	}
	out, ok = preflight(t, st, nl, closed, "--open-firewall")
	if !ok || !strings.Contains(out, "would open the ports in iptables for any address") {
		t.Errorf("--open-firewall alone on a closed host: ok=%v\n%s", ok, out)
	}

	// Nothing here closes the ports, and the installer never turns a firewall
	// on, so the addresses would restrict nothing: say so.
	out, ok = preflight(t, st, nl, modernHost(), "--open-firewall", "--from", "192.0.2.44")
	if !ok || !strings.Contains(out, "--from changes nothing") {
		t.Errorf("--from on an open host: ok=%v\n%s", ok, out)
	}

	sysv := oldDebian()
	sysv.iptables = closedByIptables
	_, hi := highPortNode(t)
	if out, ok := preflight(t, st, hi, sysv, "--open-firewall", "--from", "192.0.2.44"); !ok {
		t.Errorf("a sysvinit host can open its ports too:\n%s", out)
	}

	oldSystemd := closed
	oldSystemd.systemd = "229"
	withUfw := modernHost()
	withUfw.ufw = true
	for _, c := range []struct {
		name string
		h    fakeHost
		args []string
		want string
	}{
		{"--from alone", closed, []string{"--from", "192.0.2.44"}, "--from needs --open-firewall"},
		{"a host name", closed, []string{"--open-firewall", "--from", "relay.example.org"}, "--from relay.example.org: not an IPv4 address or network"},
		{"an IPv6 address", closed, []string{"--open-firewall", "--from", "192.0.2.44,2001:db8::1"}, "--from 2001:db8::1: not an IPv4 address or network"},
		{"another firewall manager", withUfw, []string{"--open-firewall", "--from", "192.0.2.44"}, "--from works only with plain iptables rules"},
		// The rules are put back by the service itself at every start, which
		// takes a systemd that can run one command of a unit as root.
		{"systemd before 231", oldSystemd, []string{"--open-firewall"}, "needs systemd 231"},
	} {
		out, ok := preflight(t, st, nl, c.h, c.args...)
		if ok || !strings.Contains(out, c.want) {
			t.Errorf("%s: ok=%v, want refusal containing %q\n%s", c.name, ok, c.want, out)
		}
	}
}

// The helper the installer leaves on a host with plain iptables rules is run
// here with a stand-in iptables that writes down what it was asked to do. A
// wrong rule either leaves the node closed or opens it to everyone.
func TestFirewallHelperRules(t *testing.T) {
	st := testState(t)
	script, err := installScript(st, st.node("nl1"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)<<'OBHOD_FIREWALL_EOF'\n(.*?)\nOBHOD_FIREWALL_EOF`).FindSubmatch(script)
	if m == nil {
		t.Fatal("the installer carries no firewall helper")
	}
	// The helper does nothing unless the installer wires it in: the service
	// runs it at every start, and removing the node takes the rules out.
	for _, want := range []string{
		`fwhook="ExecStartPre=-+$PREFIX/bin/firewall open"`,
		`if [ -x $PREFIX/bin/firewall ]; then $PREFIX/bin/firewall open || true; fi`,
		`if [ -x "$PREFIX/bin/firewall" ]; then "$PREFIX/bin/firewall" close || true; fi`,
	} {
		if !strings.Contains(string(script), want) {
			t.Errorf("installer lacks %q", want)
		}
	}
	dir := t.TempDir()
	for _, d := range []string{"bin", "etc", "stub"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	helper, conf, log := filepath.Join(dir, "bin", "firewall"), filepath.Join(dir, "etc", "firewall.conf"), filepath.Join(dir, "log")
	if err := os.WriteFile(helper, append(m[1], '\n'), 0o755); err != nil {
		t.Fatal(err)
	}
	stub := fmt.Sprintf("#!/bin/sh\necho \"$*\" >> %s\n", log)
	if err := os.WriteFile(filepath.Join(dir, "stub", "iptables"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	// run returns what iptables was asked to do. PATH holds nothing but the
	// stand-in: the helper runs at boot and must not lean on other tools.
	run := func(action, settings string) string {
		t.Helper()
		if err := os.WriteFile(conf, []byte(settings), 0o600); err != nil {
			t.Fatal(err)
		}
		os.Remove(log)
		cmd := exec.Command("/bin/sh", helper, action)
		cmd.Env = []string{"PATH=" + filepath.Join(dir, "stub")}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", action, err, out)
		}
		b, _ := os.ReadFile(log)
		return string(b)
	}
	// Whatever an earlier run left is taken out first, so a second run does
	// not pile the rules up.
	const clear = "-D INPUT -j OBHOD\n-F OBHOD\n-X OBHOD\n"

	got := run("open", "TCP='443 8443'\nUDP='443'\nFROM='192.0.2.44 198.51.100.0/24'\n")
	want := clear + `-N OBHOD
-A OBHOD -p tcp -s 192.0.2.44 --dport 443 -j ACCEPT
-A OBHOD -p tcp -s 192.0.2.44 --dport 8443 -j ACCEPT
-A OBHOD -p udp -s 192.0.2.44 --dport 443 -j ACCEPT
-A OBHOD -p tcp -s 198.51.100.0/24 --dport 443 -j ACCEPT
-A OBHOD -p tcp -s 198.51.100.0/24 --dport 8443 -j ACCEPT
-A OBHOD -p udp -s 198.51.100.0/24 --dport 443 -j ACCEPT
-I INPUT 1 -j OBHOD
`
	if got != want {
		t.Errorf("open for two sources:\n got:\n%s\nwant:\n%s", got, want)
	}

	got = run("open", "TCP='8443'\nUDP=''\nFROM=''\n")
	want = clear + "-N OBHOD\n-A OBHOD -p tcp -s 0.0.0.0/0 --dport 8443 -j ACCEPT\n-I INPUT 1 -j OBHOD\n"
	if got != want {
		t.Errorf("open for everyone:\n got:\n%s\nwant:\n%s", got, want)
	}

	if got = run("close", "TCP='443'\nUDP='443'\nFROM='192.0.2.44'\n"); got != clear {
		t.Errorf("close must only take the rules out:\n%s", got)
	}
}

func TestPreflightOptions(t *testing.T) {
	st := testState(t)
	nl := st.node("nl1")

	h := modernHost()
	h.missing = []string{"unzip"}
	out, ok := preflight(t, st, nl, h, "--install-deps")
	if !ok || !strings.Contains(out, "would install: unzip") {
		t.Errorf("--install-deps: ok=%v\n%s", ok, out)
	}

	// With a local archive there is nothing to download, so no curl needed.
	zip := filepath.Join(t.TempDir(), "xray.zip")
	if err := os.WriteFile(zip, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	h = modernHost()
	h.missing = []string{"curl"}
	if out, ok := preflight(t, st, nl, h, "--xray-zip", zip); !ok {
		t.Errorf("--xray-zip without curl refused:\n%s", out)
	}
	if out, ok := preflight(t, st, nl, modernHost(), "--xray-zip", zip+".absent"); ok || !strings.Contains(out, "no such file") {
		t.Errorf("missing archive accepted:\n%s", out)
	}

	if out, ok := preflight(t, st, nl, modernHost(), "--frobnicate"); ok || !strings.Contains(out, "unknown option --frobnicate") {
		t.Errorf("unknown option accepted:\n%s", out)
	}
}

// The installer must not reach for the package manager, the firewall or
// kernel settings unless asked: it may be running on a host that does other
// work.
func TestInstallerWideChangesAreOptIn(t *testing.T) {
	st := testState(t)
	script, err := installScript(st, st.node("nl1"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(script)
	if strings.Contains(s, "sysctl --system") || strings.Contains(s, "sysctl -q --system") {
		t.Error("re-applying every sysctl file can undo hand-made settings on the host")
	}
	guards := map[string]string{
		"apt-get install":                `if [ -n "$need" ]; then`,
		"/etc/sysctl.d/99-obhod.conf <<": `if [ "$tune" = yes ]; then`,
		"ufw allow":                      `if [ "$firewall" = yes ] && [ "$fw" = ufw ]; then`,
		"firewall-cmd -q --permanent":    `elif [ "$firewall" = yes ] && [ "$fw" = firewalld ]; then`,
		`etc/firewall.conf" <<`:          `if [ "$firewall" = yes ] && [ "$fw" = iptables ]; then`,
	}
	for action, guard := range guards {
		a, g := strings.Index(s, action), strings.Index(s, guard)
		if a < 0 || g < 0 || g > a {
			t.Errorf("%q must come after its guard %q", action, guard)
		}
	}
	// Tools are only installed when --install-deps was given: without it a
	// missing tool is a preflight refusal, tested above.
	if !strings.Contains(s, `if [ -n "$need" ] && [ "$deps" = no ]; then`) {
		t.Error("missing tools must be refused unless --install-deps is given")
	}
}

// Xray picks the config parser by file extension and refuses a name it does
// not know ("Failed to get format of .../config.json.new"), so the candidate
// config must carry a .json name while it is being checked.
func TestInstallerChecksConfigUnderJSONName(t *testing.T) {
	st := testState(t)
	script, err := installScript(st, st.node("nl1"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^\s*local new="([^"]+)"$`).FindStringSubmatch(string(script))
	if m == nil {
		t.Fatal("cannot find where the installer names the candidate config")
	}
	if !strings.HasSuffix(m[1], ".json") {
		t.Errorf("candidate config is %q: Xray cannot tell its format", m[1])
	}
}

func TestNodesBlockOutboundSMTP(t *testing.T) {
	st := testState(t)
	for _, n := range st.Nodes {
		c := roundTrip(t, serverConfig(st, n))
		found := false
		for _, r := range c["routing"].(map[string]any)["rules"].([]any) {
			rm := r.(map[string]any)
			if rm["port"] == "25" && rm["network"] == "tcp" && rm["outboundTag"] == "block" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: outbound TCP/25 is not blocked", n.Name)
		}
	}
}
