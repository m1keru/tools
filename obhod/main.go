// Command obhod builds and operates a small, redundant set of censorship
// circumvention nodes: it keeps the keys, renders the server installers and
// client configs, and diagnoses which kind of block a node is under.
package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

const usage = `obhod: несколько независимых транспортов на нескольких узлах, одна точка управления.

  obhod init                         создать состояние (obhod.json) с пользователем "me"
  obhod user add ИМЯ | rm ИМЯ        добавить или отозвать пользователя
  obhod node add -name N -addr IP -target САЙТ:443 [-upstream EXIT] ...
                                     добавить выходной узел, а с -upstream: relay перед ним
  obhod node rotate -name N [-addr IP] [-target САЙТ:443] [-rekey]
                                     сменить адрес, сайт-цель или все ключи узла
  obhod node rm ИМЯ                  удалить узел
  obhod set [-fp F] [-xray V]        отпечаток TLS клиентов, версия Xray на серверах
  obhod show                         узлы и пользователи, без секретов
  obhod render [-out DIR]            собрать установщики серверов и клиентские конфиги
  obhod probe [-burst] [УЗЕЛ...]     проверить узлы из этой сети и назвать тип блокировки

Файл состояния: флаг -state или переменная OBHOD_STATE, по умолчанию ./obhod.json.
В нём приватные ключи: не кладите его в git. Подробности: README.md.
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "obhod:", err)
		os.Exit(1)
	}
}

func newFlags(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	def := os.Getenv("OBHOD_STATE")
	if def == "" {
		def = "obhod.json"
	}
	return fs, fs.String("state", def, "файл состояния")
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Print(usage)
		return nil
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "init":
		return cmdInit(rest)
	case "user":
		return cmdUser(rest)
	case "node":
		return cmdNode(rest)
	case "set":
		return cmdSet(rest)
	case "show":
		return cmdShow(rest)
	case "render":
		return cmdRender(rest)
	case "probe":
		return cmdProbe(rest)
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	}
	return fmt.Errorf("unknown command %q; run `obhod help`", cmd)
}

func cmdInit(args []string) error {
	fs, path := newFlags("init")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, err := os.Stat(*path); err == nil {
		return fmt.Errorf("%s already exists; refusing to overwrite keys", *path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	st := newState()
	u, err := newUser("me")
	if err != nil {
		return err
	}
	st.Users = append(st.Users, u)
	if err := st.save(*path); err != nil {
		return err
	}
	fmt.Printf("создан %s (права 0600). Дальше: obhod node add -name ... -addr ... -target ...\n", *path)
	return nil
}

func cmdUser(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: obhod user add NAME | obhod user rm NAME")
	}
	fs, path := newFlags("user")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: obhod user add NAME | obhod user rm NAME")
	}
	name := fs.Arg(0)
	st, err := loadState(*path)
	if err != nil {
		return err
	}
	switch args[0] {
	case "add":
		if st.user(name) != nil {
			return fmt.Errorf("user %q already exists", name)
		}
		u, err := newUser(name)
		if err != nil {
			return err
		}
		st.Users = append(st.Users, u)
	case "rm":
		if st.user(name) == nil {
			return fmt.Errorf("no user %q", name)
		}
		var keep []*User
		for _, u := range st.Users {
			if u.Name != name {
				keep = append(keep, u)
			}
		}
		st.Users = keep
	default:
		return fmt.Errorf("unknown user command %q", args[0])
	}
	if err := st.save(*path); err != nil {
		return err
	}
	fmt.Println("готово. Список пользователей зашит в конфиг каждого узла: выполните obhod render")
	fmt.Println("и перезапустите install.sh на всех узлах, иначе изменение не подействует.")
	return nil
}

func cmdNode(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: obhod node add|rotate|rm ...")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "add":
		fs, path := newFlags("node add")
		var o nodeOpts
		fs.StringVar(&o.Name, "name", "", "имя узла: латинские буквы и цифры")
		fs.StringVar(&o.Address, "addr", "", "IP или домен, по которому узел видят клиенты")
		fs.StringVar(&o.Target, "target", "", "сайт-цель REALITY, host:443")
		fs.StringVar(&o.ServerName, "sni", "", "имя сервера, если отличается от хоста в -target")
		fs.StringVar(&o.Upstream, "upstream", "", "имя выходного узла: делает этот узел relay")
		fs.IntVar(&o.XHTTPPort, "xhttp-port", 443, "TCP-порт XHTTP+REALITY, 0 отключает")
		fs.IntVar(&o.VisionPort, "vision-port", 8443, "TCP-порт Vision+REALITY, 0 отключает")
		fs.IntVar(&o.Hy2Port, "hy2-port", 443, "UDP-порт Hysteria2, 0 отключает")
		fs.BoolVar(&o.AllowRU, "allow-ru", false, "не запрещать российские адреса; relay с этим флагом обслуживает их сам, со своего адреса")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if o.Name == "" || o.Address == "" || o.Target == "" {
			return errors.New("node add needs -name, -addr and -target")
		}
		st, err := loadState(*path)
		if err != nil {
			return err
		}
		if st.node(o.Name) != nil {
			return fmt.Errorf("node %q already exists", o.Name)
		}
		n, err := newNode(o)
		if err != nil {
			return err
		}
		st.Nodes = append(st.Nodes, n)
		if err := st.save(*path); err != nil {
			return err
		}
		warnTarget(n)
		fmt.Printf("узел %s добавлен. Дальше: obhod render, затем install.sh на сервере.\n", n.Name)
		if n.IsRelay() {
			fmt.Printf("Relay получает свою учётную запись на %s: переустановите и %s.\n", n.Upstream, n.Upstream)
		}
		return nil

	case "rotate":
		fs, path := newFlags("node rotate")
		name := fs.String("name", "", "имя узла")
		addr := fs.String("addr", "", "новый адрес")
		target := fs.String("target", "", "новый сайт-цель REALITY, host:443")
		sni := fs.String("sni", "", "новое имя сервера")
		rekey := fs.Bool("rekey", false, "заменить все ключи, пути и пароли узла")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		st, err := loadState(*path)
		if err != nil {
			return err
		}
		n := st.node(*name)
		if n == nil {
			return fmt.Errorf("no node %q", *name)
		}
		if *addr == "" && *target == "" && *sni == "" && !*rekey {
			return errors.New("node rotate: nothing to change; give -addr, -target, -sni or -rekey")
		}
		if *addr != "" {
			n.Address = *addr
		}
		if *target != "" {
			host, _, err := net.SplitHostPort(*target)
			if err != nil {
				return fmt.Errorf("target %q must be host:port, for example www.example.com:443", *target)
			}
			n.Reality.Target, n.Reality.ServerName = *target, host
		}
		if *sni != "" {
			n.Reality.ServerName = *sni
		}
		if (*target != "" || *sni != "") && !*rekey {
			// The Hysteria2 certificate carries the server name.
			if n.Hy2.CertPEM, n.Hy2.KeyPEM, n.Hy2.CertSHA256, err = newSelfSignedCert(n.Reality.ServerName); err != nil {
				return err
			}
		}
		if *rekey {
			if err := n.rekey(); err != nil {
				return err
			}
		}
		if err := st.save(*path); err != nil {
			return err
		}
		warnTarget(n)
		fmt.Printf("узел %s изменён. Выполните obhod render, переустановите узел и раздайте клиентам новые ссылки.\n", n.Name)
		if rs := st.relaysOf(n.Name); len(rs) > 0 {
			var names []string
			for _, r := range rs {
				names = append(names, r.Name)
			}
			fmt.Printf("На этот узел ходят relay: %s. Переустановите и их.\n", strings.Join(names, ", "))
		}
		return nil

	case "rm":
		fs, path := newFlags("node rm")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return errors.New("usage: obhod node rm NAME")
		}
		name := fs.Arg(0)
		st, err := loadState(*path)
		if err != nil {
			return err
		}
		if st.node(name) == nil {
			return fmt.Errorf("no node %q", name)
		}
		if rs := st.relaysOf(name); len(rs) > 0 {
			return fmt.Errorf("node %q is the upstream of relay %q; remove the relay first", name, rs[0].Name)
		}
		var keep []*Node
		for _, n := range st.Nodes {
			if n.Name != name {
				keep = append(keep, n)
			}
		}
		st.Nodes = keep
		if err := st.save(*path); err != nil {
			return err
		}
		fmt.Printf("узел %s удалён из состояния. На самом сервере: install.sh --uninstall (до удаления) либо снесите сервер.\n", name)
		return nil
	}
	return fmt.Errorf("unknown node command %q", sub)
}

func warnTarget(n *Node) {
	for _, w := range targetWarnings(n.Reality.ServerName) {
		fmt.Fprintf(os.Stderr, "предупреждение (%s): %s\n", n.Name, w)
	}
}

func cmdSet(args []string) error {
	fs, path := newFlags("set")
	fp := fs.String("fp", "", "отпечаток TLS клиентов: firefox, chrome, safari ...")
	ver := fs.String("xray", "", "версия Xray для серверов, например v26.11.9")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *fp == "" && *ver == "" {
		return errors.New("set: give -fp and/or -xray")
	}
	st, err := loadState(*path)
	if err != nil {
		return err
	}
	if *fp != "" {
		st.Fingerprint = *fp
	}
	if *ver != "" {
		if !strings.HasPrefix(*ver, "v") {
			return fmt.Errorf("xray version %q should look like v26.11.9", *ver)
		}
		st.XrayVersion = *ver
	}
	if err := st.save(*path); err != nil {
		return err
	}
	fmt.Println("готово. Выполните obhod render; отпечаток меняет клиентские конфиги, версия Xray: установщики.")
	return nil
}

func cmdShow(args []string) error {
	fs, path := newFlags("show")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := loadState(*path)
	if err != nil {
		return err
	}
	fmt.Printf("Xray %s, отпечаток TLS клиентов: %s\n\nУзлы:\n", st.XrayVersion, st.Fingerprint)
	for _, n := range st.Nodes {
		role := "exit"
		if n.IsRelay() {
			role = "relay -> " + n.Upstream
		}
		fmt.Printf("  %-10s %-16s %-22s xhttp %-9s vision %-9s hy2 %-9s цель %s\n",
			n.Name, role, n.Address, portLabel("tcp", n.XHTTP.Port), portLabel("tcp", n.Vision.Port),
			portLabel("udp", n.Hy2.Port), n.Reality.Target)
	}
	fmt.Println("\nПользователи:")
	for _, u := range st.Users {
		fmt.Printf("  %s\n", u.Name)
	}
	return nil
}

func portLabel(proto string, port int) string {
	if port == 0 {
		return "выкл"
	}
	return fmt.Sprintf("%s/%d", proto, port)
}

func cmdRender(args []string) error {
	fs, path := newFlags("render")
	out := fs.String("out", "out", "каталог для результата")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := loadState(*path)
	if err != nil {
		return err
	}
	files, err := render(st, *out)
	if err != nil {
		return err
	}
	for _, f := range files {
		fmt.Println(f)
	}
	fmt.Printf("\n%d файлов. В них учётные данные: не публикуйте каталог %s.\n", len(files), *out)
	return nil
}

func cmdProbe(args []string) error {
	fs, path := newFlags("probe")
	o := defaultProbeOpts()
	fs.DurationVar(&o.Timeout, "timeout", o.Timeout, "сколько ждать ответа, прежде чем считать пакеты потерянными")
	fs.StringVar(&o.Path, "path", o.Path, "что запрашивать у сайта-цели; крупный файл даёт точнее результат")
	fs.BoolVar(&o.Burst, "burst", false, "нарочно вызвать правило всплеска (узел может замереть на 2 минуты)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := loadState(*path)
	if err != nil {
		return err
	}
	nodes := st.Nodes
	if fs.NArg() > 0 {
		nodes = nil
		for _, name := range fs.Args() {
			n := st.node(name)
			if n == nil {
				return fmt.Errorf("no node %q", name)
			}
			nodes = append(nodes, n)
		}
	}
	if len(nodes) == 0 {
		return errors.New("no nodes to probe")
	}
	fmt.Println("Проверка идёт из этой сети, с выключенным VPN. Результат относится только к ней:")
	fmt.Println("у другого оператора и в другом регионе он может быть иным.")
	bad := 0
	for i, n := range nodes {
		if i > 0 {
			time.Sleep(o.Gap)
		}
		r := probeNode(n, o)
		printReport(os.Stdout, r)
		if r.Verdict != vClean {
			bad++
		}
	}
	if bad > 0 {
		return fmt.Errorf("%d of %d nodes are not clean", bad, len(nodes))
	}
	return nil
}
