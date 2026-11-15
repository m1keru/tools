package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// probe looks at a node the way the censor lets this network see it, without
// speaking any tunnel protocol. A plain TLS client that fails REALITY
// authentication is forwarded to the node's target site, so every byte of the
// real site's answer travels the same path, from the same address, as tunnel
// traffic would. That is enough to tell the block types apart, and each one
// calls for a different fix.

// Stage outcomes.
const (
	stOK      = "ok"
	stTimeout = "timeout" // packets vanish: the signature of a silent drop
	stRefused = "refused" // the host answered, nothing listens
	stReset   = "reset"
	stBadCert = "badcert"
	stStalled = "stalled" // data flowed, then stopped without a close
	stShort   = "short"   // the site closed before enough data flowed
	stError   = "error"
	stSkipped = "-"
)

// Verdicts.
const (
	vClean        = "CLEAN"
	vInconclusive = "INCONCLUSIVE"
	vIPBlocked    = "IP_BLOCKED"
	vServiceDown  = "SERVICE_DOWN"
	vTLSBlocked   = "TLS_BLOCKED"
	vBadTarget    = "BAD_TARGET"
	vVolumeFreeze = "VOLUME_FREEZE"
	vBurstRule    = "BURST_RULE"
)

type probeOpts struct {
	Timeout time.Duration // how long silence lasts before it counts as a drop
	Bytes   int64         // wire bytes one connection must carry to pass
	Path    string        // what to request from the target site
	Burst   bool          // deliberately provoke the handshake-burst rule
	Gap     time.Duration // pause between handshakes to one node
	RootCAs *x509.CertPool
}

func defaultProbeOpts() probeOpts {
	return probeOpts{Timeout: 8 * time.Second, Bytes: 96 << 10, Path: "/", Gap: 1500 * time.Millisecond}
}

type portReport struct {
	Port     int
	Kind     string
	TCP      string
	TLS      string
	Volume   string
	Received int64
	Requests int
	Detail   string
}

type nodeReport struct {
	Node    *Node
	Ports   []portReport
	Burst   string
	Verdict string
}

// countConn counts bytes as they come off the wire, TLS records and all,
// because that is the number the censor's per-connection budget is spent in.
type countConn struct {
	net.Conn
	n *atomic.Int64
}

func (c countConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.n.Add(int64(n))
	return n, err
}

func classify(err error) string {
	var ne net.Error
	var cve *tls.CertificateVerificationError
	switch {
	case err == nil:
		return stOK
	case errors.As(err, &cve):
		return stBadCert
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded),
		errors.As(err, &ne) && ne.Timeout():
		return stTimeout
	case errors.Is(err, syscall.ECONNREFUSED):
		return stRefused
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return stReset
	}
	return stError
}

// handshake opens TCP and completes TLS with the node's server name.
func handshake(n *Node, port int, o probeOpts, counter *atomic.Int64) (conn *tls.Conn, tcp, tlsSt string, err error) {
	raw, err := net.DialTimeout("tcp", hostPort(n.Address, port), o.Timeout)
	if err != nil {
		return nil, classify(err), stSkipped, err
	}
	var c net.Conn = raw
	if counter != nil {
		c = countConn{raw, counter}
	}
	tc := tls.Client(c, &tls.Config{
		ServerName: n.Reality.ServerName,
		NextProtos: []string{"http/1.1"},
		RootCAs:    o.RootCAs,
		MinVersion: tls.VersionTLS12,
	})
	_ = tc.SetDeadline(time.Now().Add(o.Timeout))
	if err = tc.Handshake(); err != nil {
		raw.Close()
		return nil, stOK, classify(err), err
	}
	return tc, stOK, stOK, nil
}

// volume keeps requesting the target's page over one connection until the
// connection has carried o.Bytes or stops delivering.
func volume(conn *tls.Conn, n *Node, o probeOpts, counter *atomic.Int64) (status string, requests int, err error) {
	br := bufio.NewReader(conn)
	// Enough round trips to cross a packet-count limit even on a tiny page,
	// few enough not to look like a flood to the target site.
	const maxRequests = 60
	for counter.Load() < o.Bytes && requests < maxRequests {
		_ = conn.SetDeadline(time.Now().Add(o.Timeout))
		_, err = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\n"+
			"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0\r\n"+
			"Accept: */*\r\nAccept-Encoding: identity\r\nConnection: keep-alive\r\n\r\n", o.Path, n.Reality.ServerName)
		if err != nil {
			return stalledOr(classify(err), requests), requests, err
		}
		resp, rerr := http.ReadResponse(br, nil)
		if rerr != nil {
			return stalledOr(classify(rerr), requests), requests, rerr
		}
		_, cerr := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		requests++
		if cerr != nil {
			return stalledOr(classify(cerr), requests), requests, cerr
		}
		if resp.Close {
			break
		}
	}
	if counter.Load() < o.Bytes {
		return stShort, requests, nil
	}
	return stOK, requests, nil
}

// stalledOr maps a mid-stream timeout to "stalled", and a close by the site
// after it has already answered to "short": the former is the censor's
// freeze, the latter is an ordinary keep-alive limit.
func stalledOr(st string, requests int) string {
	switch {
	case st == stTimeout:
		return stStalled
	case st == stReset && requests > 0:
		return stShort
	}
	return st
}

func probeNode(n *Node, o probeOpts) nodeReport {
	rep := nodeReport{Node: n, Burst: stSkipped}
	type tcpPort struct {
		port int
		kind string
	}
	var ports []tcpPort
	if n.XHTTP.Port != 0 {
		ports = append(ports, tcpPort{n.XHTTP.Port, kindXHTTP})
	}
	if n.Vision.Port != 0 {
		ports = append(ports, tcpPort{n.Vision.Port, kindVision})
	}

	volumeDone := false
	for i, p := range ports {
		if i > 0 {
			time.Sleep(o.Gap)
		}
		pr := portReport{Port: p.port, Kind: p.kind, Volume: stSkipped}
		var counter atomic.Int64
		conn, tcp, tlsSt, err := handshake(n, p.port, o, &counter)
		pr.TCP, pr.TLS = tcp, tlsSt
		if err != nil {
			pr.Detail = err.Error()
			rep.Ports = append(rep.Ports, pr)
			continue
		}
		// The byte budget is per address, so one port is enough to test it.
		if !volumeDone {
			volumeDone = true
			pr.Volume, pr.Requests, err = volume(conn, n, o, &counter)
			if err != nil {
				pr.Detail = err.Error()
			}
		}
		pr.Received = counter.Load()
		conn.Close()
		rep.Ports = append(rep.Ports, pr)
	}

	rep.Verdict = verdict(rep)
	if o.Burst && (rep.Verdict == vClean || rep.Verdict == vInconclusive) && len(ports) > 0 {
		time.Sleep(o.Gap)
		rep.Burst = burst(n, ports[0].port, o)
		if rep.Burst == stTimeout {
			rep.Verdict = vBurstRule
		}
	}
	return rep
}

// burst opens handshakes faster than the censor tolerates and reports whether
// they start to hang. It returns stOK when all of them complete.
func burst(n *Node, port int, o probeOpts) string {
	const count = 6
	for i := 0; i < count; i++ {
		if i > 0 {
			time.Sleep(250 * time.Millisecond)
		}
		conn, tcp, tlsSt, _ := handshake(n, port, o, nil)
		if conn != nil {
			conn.Close()
			continue
		}
		if tcp == stTimeout || tlsSt == stTimeout {
			return stTimeout
		}
		return stError
	}
	return stOK
}

func verdict(r nodeReport) string {
	if len(r.Ports) == 0 {
		return vInconclusive
	}
	allTimeout, allRefused := true, true
	for _, p := range r.Ports {
		allTimeout = allTimeout && p.TCP == stTimeout
		allRefused = allRefused && p.TCP == stRefused
	}
	switch {
	case allTimeout:
		return vIPBlocked
	case allRefused:
		return vServiceDown
	}
	sawShort := false
	for _, p := range r.Ports {
		switch {
		case p.TLS == stBadCert:
			return vBadTarget
		case p.TCP == stOK && (p.TLS == stTimeout || p.TLS == stReset):
			return vTLSBlocked
		case p.Volume == stStalled:
			return vVolumeFreeze
		case p.Volume == stShort || p.Volume == stReset || p.Volume == stError:
			sawShort = true
		}
	}
	if sawShort {
		return vInconclusive
	}
	for _, p := range r.Ports {
		if p.TCP != stOK || p.TLS != stOK {
			return vInconclusive
		}
	}
	return vClean
}

// advice is the runbook: what each verdict means and what to do about it.
var advice = map[string]string{
	vClean: `Путь до узла чист: TCP, TLS и объём проходят.
   Если профили в клиенте всё равно не работают, цензор реагирует на поведение туннеля,
   а не на адрес: переключите транспорт (xhttp -> hy2 -> vision), обновите Xray в клиенте,
   смените отпечаток TLS (obhod set -fp ...), но не во время заморозки.`,
	vInconclusive: `Недостаточно данных: сайт-цель закрыл соединение раньше, чем набрался объём, либо
   порты ведут себя по-разному. Повторите с -path на крупный файл сайта-цели
   (картинка, js) или проверьте узел с зарубежной машины.`,
	vIPBlocked: `Адрес не отвечает по TCP: пакеты пропадают молча. Если с зарубежной машины порт открыт,
   адрес в чёрном списке. Никакой транспорт на этом адресе не поможет:
   смените IP (лучше другая /24 или другой хостер): obhod node rotate -name ... -addr ... -rekey,
   а пока работайте через второй узел или через relay.`,
	vServiceDown: `Хост отвечает, но порт закрыт: это не блокировка. Сервис не запущен либо порт закрыт
   в firewall хостера. На сервере: systemctl status obhod-xray; journalctl -u obhod-xray -n 50.`,
	vTLSBlocked: `TCP открывается, TLS-рукопожатие зависает или рвётся. Это фильтр по SNI/отпечатку
   либо заморозка за всплеск рукопожатий. Подождите 130 секунд, ничего не меняя, и повторите.
   Если не прошло: смените сайт-цель: obhod node rotate -name ... -target ... (и переустановите узел).`,
	vBadTarget: `Узел отдаёт сертификат, не подходящий к имени сервера. Сайт-цель REALITY выбран неверно
   (не обслуживает это имя или не TLS 1.3), либо между вами и узлом подмена TLS.
   Проверьте цель с сервера: curl -sI https://ИМЯ и выберите другую цель.`,
	vVolumeFreeze: `Соединение замирает после первых килобайт без разрыва: адрес в списке «подозрительных»
   (заморозка по объёму, обычно 15-20 КБ). Это свойство адреса и его ASN, а не протокола:
   по TCP к этому адресу не будет работать ничего. Перенесите узел к другому хостеру/в другую ASN
   или ходите через relay. Hysteria2 (UDP) на этом же адресе может работать: проверьте вручную.`,
	vBurstRule: `Сеть наказывает частые TLS-рукопожатия к одному имени: работает правило всплеска.
   Используйте только профили xhttp (два долгоживущих соединения); vision на этой сети
   будет замирать. Сейчас подождите 130 секунд и не меняйте отпечаток TLS.`,
}

func printReport(w io.Writer, r nodeReport) {
	role := "exit"
	if r.Node.IsRelay() {
		role = "relay -> " + r.Node.Upstream
	}
	fmt.Fprintf(w, "\n== %s (%s) %s, имя сервера %s\n", r.Node.Name, role, r.Node.Address, r.Node.Reality.ServerName)
	for _, p := range r.Ports {
		line := fmt.Sprintf("   %-6s tcp/%-5d  tcp=%-8s tls=%-8s объём=%-8s", p.Kind, p.Port, p.TCP, p.TLS, p.Volume)
		if p.Volume != stSkipped {
			line += fmt.Sprintf(" получено %.1f КБ за %d запр.", float64(p.Received)/1024, p.Requests)
		}
		fmt.Fprintln(w, strings.TrimRight(line, " "))
		if p.Detail != "" {
			fmt.Fprintf(w, "          %s\n", p.Detail)
		}
	}
	if r.Node.Hy2.Port != 0 {
		fmt.Fprintf(w, "   %-6s udp/%-5d  не проверяется: на части операторов один UDP-пакет к наблюдаемому адресу\n"+
			"          блокирует его на минуты. Проверяйте вручную профилем %s-%s.\n", kindHy2, r.Node.Hy2.Port, r.Node.Name, kindHy2)
	}
	if r.Burst != stSkipped {
		fmt.Fprintf(w, "   всплеск рукопожатий: %s\n", r.Burst)
	}
	fmt.Fprintf(w, "   ВЕРДИКТ: %s\n   %s\n", r.Verdict, advice[r.Verdict])
}
