package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	tcpBusy []int  // ports something already listens on
	udpBusy []int
	missing []string // tools that are not installed
	running bool     // the node's own service is already up
	freeKB  int
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
		{"no systemd", func(h *fakeHost) { h.systemd = "" }, "systemd is required"},
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

// Ports held by an earlier run of the same node are not a conflict.
func TestPreflightAllowsUpdatingRunningNode(t *testing.T) {
	st := testState(t)
	h := modernHost()
	h.running, h.tcpBusy, h.udpBusy = true, []int{443, 8443}, []int{443}
	if out, ok := preflight(t, st, st.node("nl1"), h); !ok {
		t.Fatalf("update refused:\n%s", out)
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
