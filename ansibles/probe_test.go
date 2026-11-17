package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// site is a stand-in for a REALITY target: a real TLS site whose page is
// pageSize bytes. httptest's certificate is valid for example.com.
func site(t *testing.T, pageSize int, keepAlive bool) *httptest.Server {
	t.Helper()
	page := bytes.Repeat([]byte("x"), pageSize)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !keepAlive {
			w.Header().Set("Connection", "close")
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(page)))
		w.Write(page)
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // rejected handshakes are expected
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func portOf(t *testing.T, addr net.Addr) int {
	t.Helper()
	return addr.(*net.TCPAddr).Port
}

func probeOptsFor(srv *httptest.Server) probeOpts {
	o := defaultProbeOpts()
	o.Timeout = 400 * time.Millisecond
	o.Gap = 0
	if srv != nil {
		pool := x509.NewCertPool()
		pool.AddCert(srv.Certificate())
		o.RootCAs = pool
	}
	return o
}

func nodeAt(xhttpPort, visionPort int) *Node {
	return &Node{
		Name:    "t1",
		Address: "127.0.0.1",
		Reality: Reality{Target: "example.com:443", ServerName: "example.com"},
		XHTTP:   XHTTP{Port: xhttpPort},
		Vision:  Vision{Port: visionPort},
	}
}

// censor sits between the prober and the site and behaves like TSPU.
type censor struct {
	ln net.Listener
	// budget is how many bytes one connection may carry from the site before
	// it is frozen: packets stop, nothing is closed. Zero means no limit.
	budget int64
	// allow is how many connections get through; later ones are swallowed
	// after the TCP handshake, as the burst rule does. Zero means no limit,
	// a negative value swallows every connection.
	allow int32

	seen  atomic.Int32
	mu    sync.Mutex
	conns []net.Conn
}

func newCensor(t *testing.T, backend string, budget int64, allow int32) *censor {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &censor{ln: ln, budget: budget, allow: allow}
	t.Cleanup(func() {
		ln.Close()
		c.mu.Lock()
		defer c.mu.Unlock()
		for _, conn := range c.conns {
			conn.Close()
		}
	})
	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			c.hold(client)
			if n := c.seen.Add(1); c.allow < 0 || (c.allow > 0 && n > c.allow) {
				continue // swallowed: open, silent
			}
			go c.relay(client, backend)
		}
	}()
	return c
}

func (c *censor) hold(conn net.Conn) {
	c.mu.Lock()
	c.conns = append(c.conns, conn)
	c.mu.Unlock()
}

func (c *censor) relay(client net.Conn, backend string) {
	server, err := net.Dial("tcp", backend)
	if err != nil {
		return
	}
	c.hold(server)
	go io.Copy(server, client)
	if c.budget == 0 {
		io.Copy(client, server)
		return
	}
	io.CopyN(client, server, c.budget)
	// Frozen: keep both sides open and deliver nothing more.
}

func (c *censor) port(t *testing.T) int { return portOf(t, c.ln.Addr()) }

func TestProbeClean(t *testing.T) {
	srv := site(t, 8<<10, true)
	port := portOf(t, srv.Listener.Addr())
	r := probeNode(nodeAt(port, 0), probeOptsFor(srv))
	if r.Verdict != vClean {
		t.Fatalf("verdict %s, want %s: %+v", r.Verdict, vClean, r.Ports)
	}
	p := r.Ports[0]
	if p.Received < 96<<10 || p.Requests < 2 {
		t.Errorf("received %d bytes in %d requests; the test must fill the budget on one connection", p.Received, p.Requests)
	}
}

// The freeze the censor applies to watched addresses: the connection carries
// some 16 KB and then goes silent without closing.
func TestProbeVolumeFreeze(t *testing.T) {
	srv := site(t, 8<<10, true)
	const budget = 16 << 10
	c := newCensor(t, srv.Listener.Addr().String(), budget, 0)
	r := probeNode(nodeAt(c.port(t), 0), probeOptsFor(srv))
	if r.Verdict != vVolumeFreeze {
		t.Fatalf("verdict %s, want %s: %+v", r.Verdict, vVolumeFreeze, r.Ports)
	}
	if got := r.Ports[0].Received; got != budget {
		t.Errorf("reported %d bytes before the stall, the censor let through %d", got, budget)
	}
}

// With two TCP ports the byte budget is spent on the first only: it is a
// property of the address, and every extra handshake counts toward the burst
// rule.
func TestProbeTestsVolumeOnce(t *testing.T) {
	srv := site(t, 8<<10, true)
	port := portOf(t, srv.Listener.Addr())
	c := newCensor(t, srv.Listener.Addr().String(), 0, 0)
	r := probeNode(nodeAt(port, c.port(t)), probeOptsFor(srv))
	if r.Verdict != vClean || len(r.Ports) != 2 {
		t.Fatalf("verdict %s, ports %+v", r.Verdict, r.Ports)
	}
	if r.Ports[0].Volume != stOK || r.Ports[1].Volume != stSkipped || r.Ports[1].TLS != stOK {
		t.Errorf("ports: %+v", r.Ports)
	}
	if got := c.seen.Load(); got != 1 {
		t.Errorf("second port saw %d connections, want 1", got)
	}
}

func TestProbeTLSBlocked(t *testing.T) {
	// TCP completes, then nothing: what an SNI filter or a burst freeze looks like.
	c := newCensor(t, "", 0, -1)
	r := probeNode(nodeAt(c.port(t), 0), probeOptsFor(nil))
	if r.Verdict != vTLSBlocked {
		t.Fatalf("verdict %s, want %s: %+v", r.Verdict, vTLSBlocked, r.Ports)
	}
	if p := r.Ports[0]; p.TCP != stOK || p.TLS != stTimeout {
		t.Errorf("tcp=%s tls=%s", p.TCP, p.TLS)
	}
}

func TestProbeServiceDown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := portOf(t, ln.Addr())
	ln.Close() // nothing listens here now
	r := probeNode(nodeAt(port, 0), probeOptsFor(nil))
	if r.Verdict != vServiceDown {
		t.Fatalf("verdict %s, want %s: %+v", r.Verdict, vServiceDown, r.Ports)
	}
}

func TestProbeBadTarget(t *testing.T) {
	srv := site(t, 1<<10, true)
	o := probeOptsFor(srv)
	o.RootCAs = x509.NewCertPool() // the node's certificate chains to nothing we trust
	r := probeNode(nodeAt(portOf(t, srv.Listener.Addr()), 0), o)
	if r.Verdict != vBadTarget {
		t.Fatalf("verdict %s, want %s: %+v", r.Verdict, vBadTarget, r.Ports)
	}
}

// A site that closes after one small response cannot fill the budget, and
// that must not be reported as either clean or frozen.
func TestProbeInconclusiveWhenSiteCloses(t *testing.T) {
	srv := site(t, 1<<10, false)
	r := probeNode(nodeAt(portOf(t, srv.Listener.Addr()), 0), probeOptsFor(srv))
	if r.Verdict != vInconclusive {
		t.Fatalf("verdict %s, want %s: %+v", r.Verdict, vInconclusive, r.Ports)
	}
	if r.Ports[0].Volume != stShort {
		t.Errorf("volume = %s, want %s", r.Ports[0].Volume, stShort)
	}
}

func TestProbeBurstRule(t *testing.T) {
	srv := site(t, 8<<10, true)
	// The probe itself uses one connection; the censor then tolerates three more.
	c := newCensor(t, srv.Listener.Addr().String(), 0, 4)
	o := probeOptsFor(srv)
	o.Burst = true
	r := probeNode(nodeAt(c.port(t), 0), o)
	if r.Verdict != vBurstRule || r.Burst != stTimeout {
		t.Fatalf("verdict %s burst %s, want %s", r.Verdict, r.Burst, vBurstRule)
	}
}

func TestProbeBurstNotTriggered(t *testing.T) {
	srv := site(t, 8<<10, true)
	o := probeOptsFor(srv)
	o.Burst = true
	r := probeNode(nodeAt(portOf(t, srv.Listener.Addr()), 0), o)
	if r.Verdict != vClean || r.Burst != stOK {
		t.Fatalf("verdict %s burst %s", r.Verdict, r.Burst)
	}
}

// Burst is only worth provoking on a path that otherwise works.
func TestProbeBurstSkippedWhenAlreadyBlocked(t *testing.T) {
	srv := site(t, 8<<10, true)
	c := newCensor(t, srv.Listener.Addr().String(), 16<<10, 0)
	o := probeOptsFor(srv)
	o.Burst = true
	r := probeNode(nodeAt(c.port(t), 0), o)
	if r.Verdict != vVolumeFreeze || r.Burst != stSkipped {
		t.Fatalf("verdict %s burst %s", r.Verdict, r.Burst)
	}
	if got := c.seen.Load(); got != 1 {
		t.Errorf("node saw %d connections, want 1: no burst on a path that is already blocked", got)
	}
}

func TestVerdictTable(t *testing.T) {
	port := func(tcp, tlsSt, vol string) portReport { return portReport{TCP: tcp, TLS: tlsSt, Volume: vol} }
	cases := []struct {
		name  string
		ports []portReport
		want  string
	}{
		{"every port silent", []portReport{port(stTimeout, stSkipped, stSkipped), port(stTimeout, stSkipped, stSkipped)}, vIPBlocked},
		{"every port closed", []portReport{port(stRefused, stSkipped, stSkipped), port(stRefused, stSkipped, stSkipped)}, vServiceDown},
		{"one port silent, one fine", []portReport{port(stOK, stOK, stOK), port(stTimeout, stSkipped, stSkipped)}, vInconclusive},
		{"tls reset", []portReport{port(stOK, stReset, stSkipped)}, vTLSBlocked},
		{"freeze beats a clean second port", []portReport{port(stOK, stOK, stStalled), port(stOK, stOK, stSkipped)}, vVolumeFreeze},
		{"all clean", []portReport{port(stOK, stOK, stOK), port(stOK, stOK, stSkipped)}, vClean},
		{"no tcp transports", nil, vInconclusive},
	}
	for _, c := range cases {
		if got := verdict(nodeReport{Ports: c.ports}); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func TestClassify(t *testing.T) {
	timeout := &net.OpError{Op: "dial", Err: timeoutErr{}}
	cases := map[string]struct {
		err  error
		want string
	}{
		"nil":      {nil, stOK},
		"timeout":  {timeout, stTimeout},
		"refused":  {&net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, stRefused},
		"reset":    {&net.OpError{Op: "read", Err: syscall.ECONNRESET}, stReset},
		"eof":      {io.EOF, stReset},
		"bad cert": {&tls.CertificateVerificationError{Err: errors.New("x")}, stBadCert},
		"other":    {errors.New("boom"), stError},
	}
	for name, c := range cases {
		if got := classify(c.err); got != c.want {
			t.Errorf("%s: %s, want %s", name, got, c.want)
		}
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// Every verdict the probe can print must come with instructions.
func TestEveryVerdictHasAdvice(t *testing.T) {
	for _, v := range []string{vClean, vInconclusive, vIPBlocked, vServiceDown, vTLSBlocked, vBadTarget, vVolumeFreeze, vBurstRule} {
		if strings.TrimSpace(advice[v]) == "" {
			t.Errorf("no advice for %s", v)
		}
	}
}

func TestPrintReportMentionsUntestedUDP(t *testing.T) {
	n := nodeAt(443, 0)
	n.Hy2.Port = 443
	var buf bytes.Buffer
	printReport(&buf, nodeReport{Node: n, Burst: stSkipped, Verdict: vClean,
		Ports: []portReport{{Port: 443, Kind: kindXHTTP, TCP: stOK, TLS: stOK, Volume: stOK, Received: 100 << 10, Requests: 12}}})
	out := buf.String()
	for _, must := range []string{vClean, "udp/443", "не проверяется", "100.0 КБ"} {
		if !strings.Contains(out, must) {
			t.Errorf("report lacks %q:\n%s", must, out)
		}
	}
}
