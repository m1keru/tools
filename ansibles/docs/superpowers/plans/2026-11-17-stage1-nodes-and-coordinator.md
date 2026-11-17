# Этап 1: узлы и координатор — план работ

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** одна программа `ansibles` со встроенным Xray поднимает выходы и входы одной командой с ноутбука, координатор на выходе сам разносит подписанную карту и список людей по узлам внутри туннелей и пишет в Telegram, когда узел упал.

**Architecture:** новый код живёт во внутренних пакетах `ansibles/internal/...`, старый генератор остаётся рабочим под `ansibles legacy` до этапа 3. Владелец подписывает карту и список людей ключом Ed25519 на ноутбуке; ноутбук ставит узлы и отдаёт состояние координатору по ssh; узлы раз в минуту ходят к координатору через своё же ядро Xray на имени `coord.ansibles.invalid`.

**Tech Stack:** Go (toolchain 1.27), `github.com/xtls/xray-core` как библиотека, стандартная библиотека; bash для установщика на сервере; системные `ssh` и `sshpass`.

**Spec:** `ansibles/docs/superpowers/specs/2026-11-17-auto-update-design.md` (согласован, коммит b92d0a8). Этот план — этап 1 из таблицы «Этапы».

**Порядок выполнения:** 1, 13, затем 2–12, 14, 15. Скрипт сборки (Task 13) нужен раньше: из него берут `geoip.dat` и `geosite.dat` тесты Task 4 и `dist/VERSION` команда Task 12.

## Решения, принятые при планировании

Каждое — с ценой, если оно неверно. Владелец проверяет их первыми.

| № | Решение | Почему | Цена ошибки |
|---|---|---|---|
| R1 | Команды владельца доходят до координатора по ssh (`ansibles coord put`, `ansibles coord status` на узле координатора) | ноутбук и так ходит по ssh ставить узлы; клиента внутри туннеля до этапа 2 нет | на этапе 2 добавить путь через туннель; ssh-путь остаётся запасным |
| R2 | Список адресов для выхода «только для входов» обновляет `node add/rm` входа по ssh, а не сам узел | программа на узле работает без root; давать ей менять firewall — путь к повышению прав | если входы будут меняться без ноутбука (не в этом дизайне), понадобится привилегированный помощник |
| R3 | В firewall хоста открываются порты всех маскировок узла сразу, при установке | программа на узле firewall не трогает; закрытый «запасной» порт сломал бы этап 4 | порт без слушателя виден сканеру как закрытый (RST), не как служба |
| R4 | На этапе 1 узел слушает только основную маскировку (`Disguises[0]`) | переключение — этап 4 | нет |
| R5 | Новая карта или список людей → перезапуск ядра Xray в процессе (старое ядро закрыть, новое поднять, при неудаче вернуть старое) | просто и проверяемо; «без обрыва соединений» требуется только на этапе 4 | при каждой смене версии короткий обрыв соединений через узел |
| R6 | Старые команды переезжают под `ansibles legacy ...` | имена `node add`, `user add`, `init` нужны новым командам; нынешние узлы обслуживаются старым кодом до этапа 3 | владелец набирает `legacy` до перевода |
| R7 | Установщик нового узла `node.sh.tmpl` — копия `install.sh.tmpl` с правками; старый удаляется на этапе 3 | общий шаблон с ветками усложнил бы удаление старого | ~500 строк дублируются до этапа 3 |
| R8 | Учётные данные узла у других узлов (UUID узла) узел создаёт сам; они в списке людей (раздел «nodes»), который получают только узлы | приватное не покидает узел; клиенты UUID узлов не видят | нет |
| R9 | Состояние ноутбука — новый файл `network.json`, отдельно от старого `obhod.json` | старое продолжает работать до этапа 3 | два файла с ключами на ноутбуке до этапа 3 |
| R10 | Отпечаток TLS клиента (`fingerprint`) — поле карты | узлы собирают исходящие соединения сами | нет |
| R11 | На этапе 1 узлы получают полные `geoip.dat` и `geosite.dat` из выпуска Xray той же версии; урезание — этап 2 | урезанные нужны клиентам, не серверам | ~20 МБ лишнего на сервере |
| R12 | `ansibles alert set` сразу шлёт пробное сообщение | иначе неверный токен выяснится только при первой беде | нет |
| R13 | Версия карты и списка людей — счётчик, а не время | часы ноутбука и узлов не участвуют | нет |
| R15 | Проект и программа называются `ansibles` (решение владельца 17.11.2026). На серверах новой сети всё под этим именем: служба и пользователь `ansibles`, `/opt/ansibles`, цепочка iptables `ANSIBLES`, `coord.ansibles.invalid`. Имена старой установки — `obhod.json`, служба `obhod-xray`, `/opt/obhod`, цепочка `OBHOD`, соль `"obhod local proxy"` локального прокси — не меняются | это работающие узлы и клиенты: новое имя в старом установщике поставило бы вторую копию рядом с первой, новая соль сменила бы людям порты и пароли прокси. Уходят на этапе 3 | нет |
| R14 | `push` берёт версии выше тех, что уже у координатора | после сбоя или восстановления ноутбука из копии координатор иначе отверг бы «старую» версию | нет |

## Global Constraints

- В репозиторий не попадают адреса, имена серверов, сайты-маски, ключи, токены: `network.json`, `targets.txt`, `dist/` — в `ansibles/.gitignore`.
- Приватные ключи узла создаются на узле и не покидают его; в карту уходят только открытые.
- Подпись владельца — Ed25519; ключ только на ноутбуке. Узел и координатор принимают карту и список людей только с этой подписью и только с версией больше текущей.
- На чужом сервере сначала разведка `scripts/recon.sh` (только чтение), затем `node.sh --check`; неожиданное — стоп. Флаги `--open-firewall`, `--install-deps` — только из согласий владельца для этого хоста.
- Программа на сервере не трогает пакеты, ядро, sysctl, чужие сервисы и (вне флага согласия) firewall.
- Узлы отказывают российским направлениям, режут порт 25 и BitTorrent; журнал обращений выключен (`"access": "none"`).
- Только TCP-маскировки (XHTTP и Vision поверх REALITY). Hysteria2 нет.
- Каждый вызов ssh — отдельный процесс, без постоянных сессий; пароль только через `sshpass -f ФАЙЛ`.
- Токен Telegram-бота — только на выходах, никогда на входах.
- Сообщения владельцу (вывод команд, алерты) — по-русски; комментарии в коде — по-английски, как сейчас.
- Пороги из дизайна: «узел упал» — недоступен из-за границы 5 минут; «координатор недоступен» — выход 10 минут без связи с ним; напоминание — раз в сутки; узел ходит к координатору раз в минуту; `upgrade` ждёт здоровья узла 2 минуты.

## Review Focus

1. Узел перезапустился, а координатор недоступен — узел обязан подняться по сохранённой подписанной карте и обслуживать трафик. (Task 8: `TestRunStartsFromCacheWithoutCoordinator`.)
2. Ноутбук восстановлен из старой копии, версии ниже координаторских — `push` не должен ни упасть, ни откатить сеть. (Task 11: `TestPushBumpsAboveCoordinatorVersions`.)
3. Подпись чужим ключом, список людей вместо карты, версия не новее — отвергается везде. (Task 3: `TestOpenRejects`.)
4. Новая карта не поднимает ядро (ошибка в конфиге) — узел возвращает прежнее и продолжает работать. (Task 8: `TestRunKeepsOldCoreWhenNewFailsToStart`.)
5. `node add` прервался после отправки карты — повтор продолжает с запуска и не меняет ключи узла. (Task 7: `TestInitReusesExistingSecrets`; Task 11: `TestNodeAddResumesAfterPush`.)

---

### Task 1: Xray как библиотека, общие ключи и проверка сайта-маски

**Files:**
- Modify: `ansibles/go.mod`, `ansibles/go.sum`
- Create: `ansibles/internal/keys/keys.go` (перенос из `ansibles/keys.go`), `ansibles/internal/keys/keys_test.go`
- Create: `ansibles/internal/target/target.go` (перенос `targetProblem` из `ansibles/state.go`), `ansibles/internal/target/target_test.go` (перенос `TestTargetProblem` и помощника `tlsSite` из `config_test.go`)
- Create: `ansibles/internal/xraycore/xraycore.go`, `ansibles/internal/xraycore/xraycore_test.go`
- Modify: `ansibles/keys.go` (удалить), `ansibles/state.go`, `ansibles/main.go`, `ansibles/config_test.go` — старый код зовёт новые пакеты

**Interfaces:**
- Produces: `keys.NewX25519() (priv, pub string, err error)`, `keys.NewUUID() (string, error)`, `keys.RandHex(n int) (string, error)`, `keys.RandToken(n int) (string, error)`, `keys.NewSelfSignedCert(name string) (certPEM, keyPEM, sha256Hex string, err error)` — тела те же, что в `keys.go`; `target.Problem(target, serverName string, timeout time.Duration) string`; `xraycore.Instance` (интерфейс: `Close() error`, `Dial(ctx context.Context, network, addr string) (net.Conn, error)`), `xraycore.Start(configJSON []byte) (xraycore.Instance, error)`, `xraycore.Check(configJSON []byte) error`.

- [ ] **Step 1:** Подключить xray-core версии выпуска v26.11.9 (Go-тегов `v1.*` для неё нет, берётся коммит выпуска):
  Run: `cd ansibles && go get github.com/xtls/xray-core@676eaf66f8f05d4d558ee7a74b4736623d3feeb9 && go mod tidy`
  Expected: в `go.mod` строка `github.com/xtls/xray-core v1.…-…-676eaf66f8f0`; директива `go` поднята до требуемой xray-core.
- [ ] **Step 2:** Перенести `keys.go` в `internal/keys` с заглавными именами, `targetProblem` — в `internal/target` как `Problem`; старый код (`state.go`, `main.go`, тесты) зовёт их. Тест `TestTargetProblem` переезжает в `internal/target`.
  Run: `go test ./...`
  Expected: PASS, число тестов то же.
- [ ] **Step 3: Написать падающий тест** `TestStartAndDial` в `internal/xraycore`: конфиг `{"outbounds":[{"protocol":"freedom"}]}`; `Start` поднимает ядро; `Dial(ctx, "tcp", addr)` к локальному `httptest.NewServer` возвращает соединение, по которому `GET /` даёт 200; `Close()` без ошибки. И `TestCheckRejectsBadConfig`: `Check([]byte(`{"outbounds":[{"protocol":"nope"}]}`))` возвращает ошибку.
- [ ] **Step 4:** Run: `go test ./internal/xraycore/` — Expected: FAIL (пакета нет).
- [ ] **Step 5:** Реализовать `Start` через `core.StartInstance("json", cfg)` с импортом `_ "github.com/xtls/xray-core/main/distro/all"`; `Dial` — через `core.Dial` с `xnet.ParseDestination`; `Check` — загрузка конфига без запуска (`core.LoadConfig`).
- [ ] **Step 6:** Run: `go test ./... && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o /dev/null . && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o /dev/null .` — Expected: PASS и обе сборки без ошибок.
- [ ] **Step 7: Commit** — `git commit -m "Embed xray-core and move key and target helpers to internal packages"`

### Task 2: Старые команды под `ansibles legacy`

**Files:**
- Modify: `ansibles/main.go`, `ansibles/README.md`
- Test: `ansibles/main_test.go` (создать)

**Interfaces:**
- Produces: `run(args []string) error` диспетчеризует `legacy` в старый разбор (`runLegacy(args []string) error` — нынешнее тело `run`); прочие команды добавят задачи 7, 8, 11, 12.

- [ ] **Step 1: Написать падающие тесты** `TestLegacyShowRuns` (`run([]string{"legacy","show","-state", файл})` на состоянии из `testState(t)`, сохранённом во временный файл, — без ошибки) и `TestOldCommandPointsToLegacy` (`run([]string{"render"})` возвращает ошибку, текст содержит `ansibles legacy render`).
- [ ] **Step 2:** Run: `go test -run 'TestLegacy|TestOldCommand' .` — Expected: FAIL.
- [ ] **Step 3:** Перенести нынешний `switch` в `runLegacy`; `run` знает `legacy` и новые имена; старое имя без `legacy` (`render`, `probe`, `show`, `set`, `node rotate`) → ошибка «эта команда теперь `ansibles legacy …`». Справка `usage` делится на «Новая сеть» и «legacy (до перевода узлов)».
- [ ] **Step 4:** Run: `go test ./...` — Expected: PASS.
- [ ] **Step 5:** В README все примеры старых команд получают `legacy`; одна фраза, что это до этапа 3. Commit — `git commit -m "Move the current commands under ansibles legacy"`

### Task 3: Карта, список людей и подписи (`internal/netmap`)

**Files:**
- Create: `ansibles/internal/netmap/netmap.go`, `ansibles/internal/netmap/sign.go`, `ansibles/internal/netmap/netmap_test.go`

**Interfaces:**
- Produces:
  ```go
  const (RoleExit = "exit"; RoleEntry = "entry"; ForAll = "all"; ForNodes = "nodes"
         TransportXHTTP = "xhttp"; TransportVision = "vision"
         KindMap = "map"; KindRoster = "roster")
  type Disguise struct { ID, Transport string; Port int; Target, ServerName, PublicKey, ShortID, Path, EncPublic string }
  type Node struct { Name, Role, Address string; Upstreams []string; Coordinator bool; CoordPin, For string; EntriesOnly bool; Disguises []Disguise }
  type Map struct { Version int64; Fingerprint string; Nodes []Node }
  type Person struct { Name, UUID string }
  type NodeID struct { Name, UUID string }
  type Roster struct { Version int64; People []Person; Nodes []NodeID }
  type Secrets struct { Name, NodeUUID string; Disguises map[string]DisguiseKeys; CoordCertPEM, CoordKeyPEM string }
  type DisguiseKeys struct { RealityPrivate, EncPrivate string }
  type Signed struct { Kind string; Body, Sig []byte }
  func Sign(kind string, v any, priv ed25519.PrivateKey) (Signed, error)
  func Open(s Signed, kind string, pub ed25519.PublicKey, v any) error
  func (m *Map) Validate() error
  func (r *Roster) Validate() error
  func (m *Map) Node(name string) *Node
  func (m *Map) Coordinator() *Node
  func (m *Map) ExitsFor(entry *Node) []*Node
  ```
  JSON-имена полей — snake_case (`server_name`, `public_key`, `short_id`, `enc_public`, `coord_pin`, `entries_only`, `node_uuid`, `reality_private`, `enc_private`, `coord_cert_pem`, `coord_key_pem`). Подпись покрывает `Kind + "\n" + Body`.

- [ ] **Step 1: Написать падающие тесты:**
  - `TestSignOpenRoundTrip`: карта с двумя узлами подписана и открыта тем же ключом, поля совпадают.
  - `TestOpenRejects` (табличный): чужой ключ; изменённый байт `Body`; `Signed` с `Kind=roster`, открываемый как `map`; — каждое даёт ошибку.
  - `TestMapValidate` (табличный, каждое — ошибка с названием проблемы по-русски): повтор имени; имя не `^[a-z0-9]{1,24}$`; роль не exit/entry; два координатора; координатор-вход; координатор без `CoordPin`; `EntriesOnly` у входа; `Upstreams` входа называет вход или несуществующий узел; узел без маскировок; повтор `ID` или порта маскировок одного узла; `xhttp` без `Path` или `EncPublic`; `For` не `all`/`nodes`. Карта без узлов — допустима.
  - `TestExitsForEmptyUpstreamsMeansAllExits`: вход без `Upstreams` получает все выходы в порядке карты; с `Upstreams` — только названные, в их порядке.
  - `TestRosterValidate`: повтор имени человека или узла, UUID не в формате 8-4-4-4-12 — ошибка.
- [ ] **Step 2:** Run: `go test ./internal/netmap/` — Expected: FAIL.
- [ ] **Step 3:** Реализовать. Проверка имён — та же регулярка, что `validName` в `state.go`.
- [ ] **Step 4:** Run: `go test ./internal/netmap/` — Expected: PASS.
- [ ] **Step 5: Commit** — `git commit -m "Add the signed node map and people list"`

### Task 4: Конфиг Xray для узла (`internal/xcfg`)

**Files:**
- Create: `ansibles/internal/xcfg/xcfg.go`, `ansibles/internal/xcfg/xcfg_test.go`, `ansibles/internal/xcfg/geo_test.go` (помощник `requireGeodata`)

**Interfaces:**
- Consumes: `netmap.Map`, `netmap.Roster`, `netmap.Secrets` (Task 3); `xraycore.Check` (Task 1).
- Produces:
  ```go
  const CoordHost = "coord.ansibles.invalid"
  const CoordLocalPort = 10443 // the coordinator's HTTPS on 127.0.0.1
  func NodeConfig(m *netmap.Map, r *netmap.Roster, sec *netmap.Secrets) ([]byte, error)
  ```
  Логику переносить из `server.go` и `client.go` (`xmux`, `realityServer`, `xhttpOutbound`, `visionOutbound`, `failover`, `ruDomains`), не меняя значений: тот же `xmux`, те же настройки `failover` (`interval 30s`, `sampling 3`, `timeout 10s`, `tolerance 0.5`), `decryption` `mlkem768x25519plus.native.600s.`, `encryption` `mlkem768x25519plus.native.0rtt.`.

Что строит `NodeConfig` для узла `sec.Name`:
- вход (inbound) — только `Disguises[0]` этого узла (R4); пользователи: все `People`; у выхода ещё все `Roster.Nodes`, кроме себя. Почта пользователя — `имя@ID маскировки`, у узлов `node-имя@ID`.
- исходящие: выход — первым `direct` (freedom), затем `block`, затем `coord`; вход — `<выход>-up` на основную маскировку каждого выхода из `ExitsFor` под своим `NodeUUID` (цены 1, 100, …), `direct`, `block`, балансировщик `upstream` с `burstObservatory`.
- `coord`: на координаторе — freedom с `redirect` `127.0.0.1:10443` и правилом `finalRules`, разрешающим ровно этот адрес и порт (имена полей сверить с `infra/conf/freedom.go` закреплённой версии xray-core); на прочих выходах — исходящее на основную маскировку координатора под своим `NodeUUID`.
- правила по порядку: домен `full:coord.ansibles.invalid` → `coord` (у входа — балансировщик `upstream`); TCP порт 25 → `block`; BitTorrent → `block`; `ruDomains` и `geoip:ru` → `block`; у входа последнее правило `tcp,udp` → балансировщик `upstream`.
- `log`: `loglevel warning`, `access none`.

- [ ] **Step 1: Написать падающие тесты** (собирают карту из координатора-выхода `a`, выхода `b`, входа `r` и роутер с людьми `me`, `anna`):
  - `TestExitAcceptsPeopleAndOtherNodes`: у `b` среди пользователей входа UUID людей и узлов `a`, `r`, но не свой.
  - `TestEntryAcceptsOnlyPeople`: у `r` только UUID людей.
  - `TestEntryUsesEveryExit`: у `r` исходящие `a-up`, `b-up`; селектор балансировщика `["a-up","b-up"]`; цены 1 и 100.
  - `TestCoordinatorSendsCoordHostToLocalPort`: у `a` правило домена `coord.ansibles.invalid` ведёт на `coord`, а `coord` — freedom с `redirect` `127.0.0.1:10443`.
  - `TestExitSendsCoordHostToCoordinator`: у `b` `coord` — VLESS на адрес и порт основной маскировки `a`, `id` = `NodeUUID` узла `b`.
  - `TestNodesRefuseRussianAndMail`: у всех трёх правила на порт 25, BitTorrent, `ruDomains`, `geoip:ru` ведут на `block`, и правило `coord` стоит раньше них.
  - `TestNodeConfigsLoadInXray`: для `a`, `b`, `r` `xraycore.Check(cfg)` без ошибки. Нужны `geoip.dat` и `geosite.dat`: `requireGeodata(t)` ставит `XRAY_LOCATION_ASSET` на `ansibles/dist` и пропускает тест с сообщением «запустите scripts/build.sh», если файлов нет.
- [ ] **Step 2:** Run: `go test ./internal/xcfg/` — Expected: FAIL.
- [ ] **Step 3:** Реализовать `NodeConfig`.
- [ ] **Step 4:** Run: `scripts/build.sh` (Task 13), затем `go test ./internal/xcfg/ -v` — Expected: PASS, ни одного SKIP.
- [ ] **Step 5: Commit** — `git commit -m "Build node Xray configs from the signed map"`

### Task 5: Алерты в Telegram (`internal/alert`)

**Files:**
- Create: `ansibles/internal/alert/alert.go`, `ansibles/internal/alert/alert_test.go`

**Interfaces:**
- Produces:
  ```go
  type Sender interface{ Send(text string) error }
  type Telegram struct { Token, ChatID, API string; Client *http.Client } // API "" means https://api.telegram.org
  func (t Telegram) Send(text string) error
  func Load(path string) (Telegram, error) // {"token": "...", "chat_id": "..."}
  ```

- [ ] **Step 1: Написать падающие тесты** с `httptest.Server` вместо API: `TestSendPostsChatAndText` (POST на `/bot<token>/sendMessage`, форма `chat_id`, `text`); `TestSendErrorHidesToken` (ответ 401 → ошибка, в тексте ошибки нет токена).
- [ ] **Step 2:** Run: `go test ./internal/alert/` — Expected: FAIL.
- [ ] **Step 3:** Реализовать; таймаут клиента 15 с.
- [ ] **Step 4:** Run: `go test ./internal/alert/` — Expected: PASS.
- [ ] **Step 5: Commit** — `git commit -m "Send owner alerts through a Telegram bot"`

### Task 6: Координатор (`internal/coord`)

**Files:**
- Create: `ansibles/internal/coord/store.go`, `ansibles/internal/coord/server.go`, `ansibles/internal/coord/health.go`, тесты `store_test.go`, `server_test.go`, `health_test.go`

**Interfaces:**
- Consumes: `netmap.*` (Task 3), `alert.Sender` (Task 5).
- Produces:
  ```go
  type Store struct{ Dir string; Owner ed25519.PublicKey }
  func (s Store) Put(m, r netmap.Signed) error              // both must open with Owner and be newer
  func (s Store) Get() (m, r netmap.Signed, err error)
  func (s Store) Versions() (mapV, rosterV int64, err error)

  type Report struct { Node, Version string; MapVersion, RosterVersion int64 }
  type NodeStatus struct { Node, Version string; MapVersion, RosterVersion int64; LastSeen, LastAlive time.Time; Down bool }
  type Health struct { DownAfter, Remind time.Duration; Alert alert.Sender; Now func() time.Time /* unexported state */ }
  func NewHealth(a alert.Sender) *Health                     // DownAfter 5m, Remind 24h, Now time.Now
  func (h *Health) Observe(node string, alive bool)
  func (h *Health) Seen(r Report)
  func (h *Health) Tick()
  func (h *Health) Snapshot() []NodeStatus

  type Server struct{ Store Store; Health *Health }
  func (s *Server) Handler() http.Handler
  // GET  /v1/state?map=N&roster=N   Authorization: Bearer <node UUID>
  //      200 {"map": Signed|null, "roster": Signed|null} — only parts newer than N; unknown UUID → 403
  // POST /v1/health  (same auth; body Report; Report.Node must belong to the UUID) → 204
  func Alive(ctx context.Context, addr, serverName string) error // TLS 1.3 handshake, 10 s
  func RunChecks(ctx context.Context, s Store, h *Health, every time.Duration) // every minute: Alive on each node's Disguises[0], then Tick, then write health.json next to the store
  ```

- [ ] **Step 1: Написать падающие тесты:**
  - `TestStorePutRejectsOlderOrForeign`: `Put` с версией не больше текущей → ошибка «версия карты 3 не новее текущей 3»; подпись чужим ключом → ошибка; после ошибки `Get` отдаёт прежнее.
  - `TestStateGivesOnlyNewerParts`: узел с актуальной картой и старым списком получает только список.
  - `TestStateRefusesUnknownUUID`: 403.
  - `TestHealthReportMustMatchUUID`: `Report.Node` чужого узла → 403.
  - `TestHealthDownAfterFiveMinutes` (подставные `Now` и `Sender`): неудачные `Observe` 4 минуты 59 секунд — ни одного сообщения; в 5:00 — одно, содержит имя узла и слово «упал»; следующие `Tick` в течение суток — ничего; через 24 часа — напоминание; удачный `Observe` — одно сообщение «снова доступен».
  - `TestHealthSingleFailureNoAlert`: чередование удачных и неудачных проверок сутки — ни одного сообщения.
- [ ] **Step 2:** Run: `go test ./internal/coord/` — Expected: FAIL.
- [ ] **Step 3:** Реализовать. Файлы стора: `map.signed`, `roster.signed`, `health.json`; запись — во временный файл и `rename`. Сообщения алертов — по-русски, с временем по UTC.
- [ ] **Step 4:** Run: `go test ./internal/coord/` — Expected: PASS.
- [ ] **Step 5: Commit** — `git commit -m "Add the coordinator: state, health checks and alerts"`

### Task 7: Ключи и маскировки нового узла (`ansibles node init`)

**Files:**
- Create: `ansibles/internal/node/init.go`, `ansibles/internal/node/init_test.go`
- Modify: `ansibles/main.go` (команда `node init`)

**Interfaces:**
- Consumes: `keys.*`, `target.Problem` (Task 1), `netmap.*` (Task 3), `xcfg.CoordHost` (Task 4).
- Produces:
  ```go
  type InitOpts struct {
      Name, Role, Address string
      Ports       []int     // one per disguise, primary first; at least 3
      Targets     []string  // candidate sites host:port, in order of preference
      Coordinator bool
      Check       func(target, serverName string) string // "" means the site fits
  }
  func Init(o InitOpts) (netmap.Node, netmap.Secrets, error)
  ```
  CLI на сервере: `ansibles node init -name N -role exit|entry -addr IP -ports P1,P2,P3 -targets S1,S2,... [-coordinator] [-etc /opt/ansibles/etc]`. Пишет `secrets.json` (0640); если файл уже есть с тем же именем узла — ничего не создаёт и печатает ту же открытую часть. Печатает одну строку `ANSIBLES_NODE {"node": <netmap.Node>, "node_uuid": "<uuid>"}`.

Маскировки по портам: `d1` xhttp, `d2` vision, `d3` xhttp, далее чередуются; каждой — свой сайт из подошедших, свои ключи REALITY (`keys.NewX25519`), `ShortID` (`RandHex(8)`), у xhttp — `Path` (`"/"+RandHex(12)`) и ключ шифрования (`NewX25519`). `For` = `all`. Координатор: `keys.NewSelfSignedCert(xcfg.CoordHost)`, `CoordPin` = её sha256.

- [ ] **Step 1: Написать падающие тесты** (подставной `Check`):
  - `TestInitMakesDisguisePerPort`: 3 порта, 4 подходящих сайта → 3 маскировки с транспортами xhttp, vision, xhttp, разными сайтами и портами; `Node.Validate` через карту из одного узла (с `Coordinator`) проходит.
  - `TestInitSkipsUnfitTargets`: первый сайт `Check` отвергает → он не используется.
  - `TestInitNeedsEnoughTargets`: подошло 2 сайта на 3 порта → ошибка «сайтов-масок прошло проверку 2 из 3».
  - `TestInitKeepsPrivateKeysOut`: ни одна строка из `Secrets` (приватные ключи, `NodeUUID`, ключ координатора) не встречается в `json.Marshal(node)`.
  - `TestInitReusesExistingSecrets`: CLI дважды с одним `-etc` → одинаковая строка `ANSIBLES_NODE`.
- [ ] **Step 2:** Run: `go test ./internal/node/ -run TestInit` — Expected: FAIL.
- [ ] **Step 3:** Реализовать `Init` и команду; `Check` в CLI — `target.Problem(t, sni, 8*time.Second)`.
- [ ] **Step 4:** Run: `go test ./internal/node/ -run TestInit` — Expected: PASS.
- [ ] **Step 5: Commit** — `git commit -m "Let a node create its own keys and disguises"`

### Task 8: Программа узла (`ansibles node run`, `ansibles node seed`, `ansibles coord put|status`)

**Files:**
- Create: `ansibles/internal/node/run.go`, `ansibles/internal/node/coordclient.go`, `ansibles/internal/node/run_test.go`
- Modify: `ansibles/main.go`

**Interfaces:**
- Consumes: `xcfg.NodeConfig`, `xcfg.CoordHost`, `xcfg.CoordLocalPort` (Task 4); `xraycore.Start`, `xraycore.Instance` (Task 1); `coord.Server`, `coord.Store`, `coord.NewHealth`, `coord.RunChecks`, `coord.Report` (Task 6); `alert.Load` (Task 5).
- Produces:
  ```go
  type Paths struct{ Etc, Var string } // /opt/ansibles/etc, /opt/ansibles/var
  type Runner struct {
      Paths    Paths
      Version  string
      Poll     time.Duration // 1m
      CoordDownAfter time.Duration // 10m; exits only
      Start    func(cfg []byte) (xraycore.Instance, error)
      Alert    alert.Sender // nil on entries
      Now      func() time.Time
  }
  func (r *Runner) Run(ctx context.Context) error
  func Seed(p Paths, in io.Reader) error // {"owner": base64, "map": Signed, "roster": Signed, "telegram": {...}|null}
  ```
  Файлы узла: `etc/owner.pub`, `etc/secrets.json`, `etc/telegram.json` (только выходы), `var/map.signed`, `var/roster.signed`, у координатора `var/coord/…`.
  Связь с координатором: HTTPS через `Instance.Dial` на `coord.ansibles.invalid:443`, проверка сертификата — только совпадение sha256 с `CoordPin` из карты (`InsecureSkipVerify` + `VerifyPeerCertificate`), `Authorization: Bearer <NodeUUID>`.
  На узле координатора ядро Xray направляет `coord.ansibles.invalid` на `127.0.0.1:10443`, где в том же процессе работает `coord.Server` с сертификатом из `secrets.json`, и `coord.RunChecks`.
  CLI: `ansibles node run [-etc] [-var]`; `ansibles node seed` (stdin); `ansibles coord put` (stdin `{"map":…, "roster":…}`; пишет через `coord.Store`, владелец — из `etc/owner.pub`); `ansibles coord status [-json]` (версии стора и `health.json`: узел, версия программы, версии карты и списка, сколько назад видели, упал ли).

- [ ] **Step 1: Написать падающие тесты** (подставные `Start`, координатор — `httptest` с тем же `coord.Server`, `Dial` подставного ядра ведёт на него):
  - `TestRunStartsFromCacheWithoutCoordinator`: координатор недоступен → `Start` вызван с конфигом из сохранённой карты, `Run` не завершается до отмены контекста.
  - `TestRunAppliesNewerRoster`: координатор отдаёт список версии 2 → он сохранён в `var/roster.signed`, `Start` вызван второй раз с конфигом, где есть новый человек, старое ядро закрыто.
  - `TestRunKeepsOldCoreWhenNewFailsToStart`: второй `Start` возвращает ошибку → снова поднят прежний конфиг, в `var` осталась прежняя версия.
  - `TestRunRejectsForeignSignature`: координатор отдаёт список, подписанный чужим ключом → не применяется.
  - `TestExitAlertsWhenCoordinatorGone`: выход без связи с координатором 9:59 — тишина, 10:00 — одно сообщение «координатор недоступен», дальше раз в сутки; у входа (`Alert` nil) — без паники.
  - `TestHealthReportCarriesVersions`: после опроса координатор получил `Report` с версией программы и версиями карты и списка.
- [ ] **Step 2:** Run: `go test ./internal/node/` — Expected: FAIL.
- [ ] **Step 3:** Реализовать `Run`, `Seed`, клиент координатора и команды.
- [ ] **Step 4:** Run: `go test ./internal/node/` — Expected: PASS.
- [ ] **Step 5: Commit** — `git commit -m "Run a node from the signed map and keep it current"`

### Task 9: Установщик узла `node.sh.tmpl`

**Files:**
- Create: `ansibles/internal/admin/node.sh.tmpl` (копия `ansibles/install.sh.tmpl` с правками ниже), `ansibles/internal/admin/nodesh.go`, `ansibles/internal/admin/nodesh_test.go` (перенос стенда `fakeHost` и тестов предпроверки из `install_test.go`)

**Interfaces:**
- Produces:
  ```go
  type NodeSh struct {
      Node       string
      Ports      []int    // all disguise ports of the node, or candidates for --check
      Init       string   // arguments for `ansibles node init`, "" on update
      Upload     string   // remote dir with ansibles, geoip.dat, geosite.dat
  }
  func RenderNodeSh(v NodeSh) ([]byte, error)
  ```
  Режимы скрипта: `--check` (как сейчас плюс строки `arch: <uname -m>` и `free-ports: <свободные из Ports>`; отказ, если есть `/opt/obhod/etc/config.json` старой установки: «сначала --uninstall старой установки obhod-xray»); без флага — установка: пользователь `ansibles`, `/opt/ansibles/{bin,etc,var,share}` (`etc` root:ansibles 0750, `var` ansibles:ansibles 0700), программа и geodata из `Upload`, служба `ansibles` (`ExecStart=/opt/ansibles/bin/ansibles node run`, `Environment=XRAY_LOCATION_ASSET=/opt/ansibles/share`, те же возможности на низкие порты, что сейчас), помощник firewall с портами всех маскировок (R3) и `--from` при согласии, затем `ansibles node init` с `Init` и печать его строки `ANSIBLES_NODE`; служба не запускается. `--start` — включить и запустить службу. `--upgrade` — новая программа из `Upload` ставится, прежняя остаётся `bin/ansibles.prev`, служба перезапускается. `--rollback` — вернуть `ansibles.prev` и перезапустить. `--uninstall` — как сейчас.

- [ ] **Step 1: Написать падающие тесты** на стенде `fakeHost`:
  - перенести `TestPreflightRefusals`, `TestPreflightSysvinitHost`, `TestSysvinitServiceShape`, `TestPreflightSeesIptablesClosingPorts`, `TestPreflightOpenFirewallFrom`, `TestFirewallHelperRules` с поправкой на новые имена (службы `ansibles`, без загрузки Xray, без `--xray-zip`, без `--tune-network`, без UDP);
  - `TestCheckReportsArchAndFreePorts`: на хосте занят 443 → вывод содержит `free-ports: 8443 2053`;
  - `TestCheckRefusesOldInstall`: есть `/opt/obhod/etc/config.json` → отказ с текстом про `--uninstall`;
  - `TestUnitRunsNodeProgram`: юнит содержит `ExecStart=/opt/ansibles/bin/ansibles node run` и `XRAY_LOCATION_ASSET=/opt/ansibles/share`.
- [ ] **Step 2:** Run: `go test ./internal/admin/ -run 'Preflight|Check|Unit|Sysvinit|Firewall'` — Expected: FAIL.
- [ ] **Step 3:** Сделать `node.sh.tmpl` и `RenderNodeSh` (`//go:embed node.sh.tmpl`).
- [ ] **Step 4:** Run: `go test ./internal/admin/` — Expected: PASS; `go test ./...` — PASS (старые тесты `install_test.go` не тронуты).
- [ ] **Step 5: Commit** — `git commit -m "Add the installer for nodes of the new network"`

### Task 10: Состояние ноутбука, ssh и список сайтов-масок

**Files:**
- Create: `ansibles/internal/admin/state.go`, `ansibles/internal/admin/ssh.go`, `ansibles/internal/admin/targets.go`, тесты `state_test.go`, `ssh_test.go`, `targets_test.go`
- Modify: `ansibles/.gitignore` (`network.json`, `network.json.tmp`, `targets.txt`, `dist/`)

**Interfaces:**
- Produces:
  ```go
  type Host struct { SSH, PassFile, Arch string; Flags []string } // Flags: consented --open-firewall, --install-deps
  type TelegramCreds struct { Token, ChatID string }
  type State struct {
      OwnerKey ed25519.PrivateKey
      Map      netmap.Map
      Roster   netmap.Roster
      Hosts    map[string]Host
      Telegram *TelegramCreds
  }
  func NewState() (*State, error)                  // owner key, person "me", Map.Fingerprint "chrome"
  func LoadState(path string) (*State, error)
  func (s *State) Save(path string) error          // 0600, temp file + rename

  type Target struct{ SSH, PassFile string }
  type Runner interface { Run(t Target, cmd string, stdin []byte) ([]byte, error) }
  type SystemSSH struct{ Retries int; Pause time.Duration } // 3, 3s
  func (SystemSSH) Run(t Target, cmd string, stdin []byte) ([]byte, error)
  func Root(t Target, cmd string) string           // "sudo -n sh -c '<cmd>'" unless the login user is root

  type Group struct{ Name, PTRSuffix string; Sites []string }
  func ParseTargets(r io.Reader) ([]Group, error)  // line: name [ptr=SUFFIX] site site ...; # comments
  func PickGroup(gs []Group, hoster, address string, lookup func(string) ([]string, error)) (Group, error)
  func OrderSites(g Group, used map[string]bool) []string // unused first, then used, both in file order
  ```
  `SystemSSH` запускает `ssh -o BatchMode=yes -o ConnectTimeout=15 ЦЕЛЬ КОМАНДА`; с `PassFile` — `sshpass -f ФАЙЛ ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1 -o ConnectTimeout=15 ЦЕЛЬ КОМАНДА`; ответ с «Permission denied» повторяет до `Retries` раз с паузой `Pause`.

- [ ] **Step 1: Написать падающие тесты:**
  - `TestStateSaveIsPrivate`: файл после `Save` — 0600; `LoadState` возвращает то же.
  - `TestSSHArgs`: команда для ключа и для пароля (проверка аргументов через подставной исполнитель); пароль не встречается в аргументах.
  - `TestSSHRetriesPermissionDenied`: подставной исполнитель дважды отвечает «Permission denied», затем успех → 3 вызова, результат успешный; на «Connection refused» — без повторов.
  - `TestRootWrapsNonRoot`: `root@h` — команда как есть; `ec2-user@h` — `sudo -n sh -c '…'` с экранированием одинарных кавычек.
  - `TestPickGroup`: по `-hoster`; по окончанию PTR (подставной `lookup`); не нашёл → ошибка «укажите -hoster или -targets».
  - `TestOrderSitesPrefersUnused`.
- [ ] **Step 2:** Run: `go test ./internal/admin/ -run 'State|SSH|Root|Pick|Order'` — Expected: FAIL.
- [ ] **Step 3:** Реализовать (исполнитель команд — поле `exec func(name string, args []string, stdin []byte) ([]byte, error)` у `SystemSSH`, по умолчанию `os/exec`).
- [ ] **Step 4:** Run: тот же — Expected: PASS.
- [ ] **Step 5: Commit** — `git commit -m "Keep the owner's state and reach hosts over ssh"`

### Task 11: Команды владельца: `init`, `node add|rm`, `user add|rm`, `status`, `alert set`

**Files:**
- Create: `ansibles/internal/admin/commands.go`, `ansibles/internal/admin/commands_test.go`
- Modify: `ansibles/main.go`

**Interfaces:**
- Consumes: всё из Task 3, 9, 10; `alert.Telegram` (Task 5).
- Produces:
  ```go
  type Env struct { State *State; StatePath string; SSH Runner; Out io.Writer; Dist string; ReconScript string; Targets []Group; Lookup func(string) ([]string, error); Dial func(network, addr string) (net.Conn, error) }
  type NodeAddOpts struct { Name, Role, Address string; Host Host; Hoster string; Targets []string; Upstreams []string; Coordinator, EntriesOnly bool }
  func NodeAdd(e Env, o NodeAddOpts) error
  func NodeRm(e Env, name string) error
  func UserAdd(e Env, name string) error
  func UserRm(e Env, name string) error
  func Status(e Env) error
  func AlertSet(e Env, tokenFile, chatID string, t alert.Sender) error
  func push(e Env) error // signs Map and Roster with versions above the coordinator's and runs `ansibles coord put` there
  ```
  Кандидаты портов: `443, 8443, 2053, 2083, 2087, 2096, 9443`; узлу нужно 3 свободных.

Порядок `NodeAdd` (каждый шаг печатает строку по-русски; любой сбой — стоп с выводом сервера):
1. Проверки: имя свободно; первый узел — выход с `-coordinator`; второго координатора нет; вход — только при наличии выхода.
2. `scripts/recon.sh` по ssh (только чтение), вывод — владельцу.
3. `node.sh --check` с кандидатами портов и согласиями → `arch`, `free-ports`; меньше 3 свободных — стоп.
4. Загрузка `dist/ansibles-linux-<arch>`, `dist/geoip.dat`, `dist/geosite.dat` в `/tmp/ansibles-upload-<имя>/` (`cat > …` через `Runner`).
5. `node.sh` (установка, `node init`) → разбор строки `ANSIBLES_NODE`.
6. Узел и его UUID — в карту и список людей (`For` = `nodes` при `EntriesOnly`); `Validate`; `push`; `Save`.
7. `ansibles node seed` на узле (владелец, подписанные части, Telegram — только выходу), затем `node.sh --start`.
8. Ждать до 2 минут (опрос `coord status -json` раз в 10 с), пока координатор не увидит узел; не увидел — стоп «узел не вышел на связь с координатором», с подсказкой смотреть журнал службы.
9. Для входа: перезапустить `node.sh` (без `Init`) на выходах с `EntriesOnly`, чтобы `--from` получил новый список адресов входов (R2).
10. Напечатать порты всех маскировок для облачной консоли и проверить с ноутбука TCP-соединением, открыты ли они (неоткрытые — предупреждение, не ошибка).

Повтор `node add` с тем же именем и адресом, когда узел уже в карте, начинает с шага 7.

- [ ] **Step 1: Написать падающие тесты** с подставным `Runner`, который пишет журнал команд и отвечает заготовками:
  - `TestNodeAddRunsStepsInOrder`: журнал — recon, `--check`, загрузки, установка, `coord put`, `node seed`, `--start`, `coord status`; состояние сохранено с узлом и UUID.
  - `TestNodeAddStopsOnFailedCheck`: `--check` с кодом ошибки → ни загрузки, ни `coord put`; состояние не изменилось.
  - `TestNodeAddResumesAfterPush`: узел уже в карте → журнал начинается с `node seed`; ключи (открытая часть в карте) не изменились.
  - `TestFirstNodeMustBeCoordinatorExit` и `TestNoSecondCoordinator`.
  - `TestEntryAddRefreshesEntriesOnlyExits`: после входа — `node.sh` на выходе с `EntriesOnly` с `--from` адресом входа.
  - `TestPushBumpsAboveCoordinatorVersions`: координатор сообщает версии 9 и 4 при локальных 3 и 2 → `coord put` получает карту 10 и список 5.
  - `TestNodeRmRefusesCoordinator`; `TestNodeRmDropsNodeAndItsUUID`.
  - `TestUserAddPushesRoster`: новый человек с UUID, `coord put` вызван, версия списка выросла.
  - `TestAlertSetSendsTestMessage`: подставной отправитель получил пробное сообщение; при ошибке отправки токен не сохранён.
- [ ] **Step 2:** Run: `go test ./internal/admin/ -run 'NodeAdd|NodeRm|First|NoSecond|Entry|Push|UserAdd|AlertSet'` — Expected: FAIL.
- [ ] **Step 3:** Реализовать команды и подключить в `main.go`: `ansibles init` (создаёт `network.json`, отказывает, если он есть), `ansibles node add -name -role -addr -ssh [-ssh-pass-file] [-hoster|-targets] [-upstream] [-coordinator] [-entries-only] [-open-firewall] [-install-deps]`, `ansibles node rm ИМЯ`, `ansibles user add|rm ИМЯ`, `ansibles status`, `ansibles alert set -token-file F -chat ID`. Флаг `-state` по умолчанию `network.json`.
- [ ] **Step 4:** Run: `go test ./...` — Expected: PASS.
- [ ] **Step 5: Commit** — `git commit -m "Add owner commands for the new network"`

### Task 12: `ansibles upgrade`

**Files:**
- Create: `ansibles/internal/admin/upgrade.go`, `ansibles/internal/admin/upgrade_test.go`
- Modify: `ansibles/main.go`

**Interfaces:**
- Consumes: `Env`, `Runner`, `RenderNodeSh` (Tasks 9–11).
- Produces: `func Upgrade(e Env, version string) error` — `version` — та, что напечатает новая программа (`dist/VERSION`).

Порядок: выходы без координатора, затем входы, координатор последним. Для узла: загрузка программы → `node.sh --upgrade` → ждать до 2 минут, пока координатор не увидит узел с новой версией (для самого координатора — пока `coord status -json` не ответит своей новой версией) → не дождался: `node.sh --rollback` и стоп с именем узла; остальные узлы не трогаются.

- [ ] **Step 1: Написать падающие тесты:** `TestUpgradeOrder` (журнал: `b`, `r`, затем `a`-координатор); `TestUpgradeRollsBackAndStops` (у `b` версия не меняется → `--rollback` на `b`, `r` и `a` не тронуты, ошибка называет `b`).
- [ ] **Step 2:** Run: `go test ./internal/admin/ -run Upgrade` — Expected: FAIL.
- [ ] **Step 3:** Реализовать и подключить `ansibles upgrade`.
- [ ] **Step 4:** Run: `go test ./...` — Expected: PASS.
- [ ] **Step 5: Commit** — `git commit -m "Upgrade nodes one by one with rollback"`

### Task 13: Сборка `scripts/build.sh`

**Files:**
- Create: `ansibles/scripts/build.sh`
- Modify: `ansibles/main.go` (`var version = "dev"`; `ansibles version`)

**Interfaces:**
- Produces: `dist/ansibles-linux-amd64`, `dist/ansibles-linux-arm64`, `dist/ansibles` (для ноутбука), `dist/geoip.dat`, `dist/geosite.dat`, `dist/VERSION`.

Сборка: `CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(git describe --always --dirty)"`. Geodata: архив `Xray-linux-64.zip` выпуска `v26.11.9` с GitHub, проверка sha256 по `.dgst`, из него `geoip.dat` и `geosite.dat`. Версия Xray в скрипте — одной строкой наверху, та же, что в `go.mod` (комментарий об этом).

- [ ] **Step 1:** Написать скрипт.
- [ ] **Step 2:** Run: `scripts/build.sh && file dist/ansibles-linux-arm64 && dist/ansibles version` — Expected: ELF aarch64; версия совпадает с `git describe`.
- [ ] **Step 3:** Run: `go test ./...` — Expected: PASS, тесты с geodata без SKIP.
- [ ] **Step 4: Commit** — `git commit -m "Build node binaries and fetch geodata"`

### Task 14: Лаборатория на одной машине

**Files:**
- Create: `ansibles/internal/lab/lab_test.go`

**Interfaces:**
- Consumes: `node.Init`, `node.Runner`, `node.Seed` (Tasks 7–8), `netmap.Sign` (Task 3), `coord.Health` поля `DownAfter` (Task 6).

Стенд: выход-координатор `a`, выход `b`, вход `r` — три `node.Runner` в одном процессе, каталоги во временной папке, адреса `127.0.0.1`, порты — свободные из `net.Listen(":0")`. Сайт-маска — локальный TLS-сервер (`httptest.NewUnstartedServer`, TLS 1.3, только X25519, ALPN `h2`), `Check` в `Init` — настоящий `target.Problem`. `Poll` 1 с, проверки координатора раз в 1 с, `DownAfter` 5 с, отправитель — подставной. Если REALITY не принимает локальный сайт-маску (ошибка рукопожатия в журнале ядра), — тест переводится на настоящий сайт за тегом сборки `labnet`, и это записывается в отчёт задачи.

- [ ] **Step 1: Написать тесты:**
  - `TestLabRosterReachesEveryNode`: новый список людей версии 2 положен в стор `a` через `coord.Store.Put` → за 10 с `coord status` видит у `a`, `b`, `r` список 2 (вход ходит к координатору через туннель выхода).
  - `TestLabStoppedNodeRaisesOneAlert`: остановить `b` → за 15 с ровно одно сообщение со словом «упал» и именем `b`; про `a` и `r` — ничего.
- [ ] **Step 2:** Run: `go test ./internal/lab/ -v -count=1` — Expected: PASS (тесты должны сначала падать, если какое-то звено не работает: проверить, временно сломав правило `coord` в `xcfg`, что `TestLabRosterReachesEveryNode` краснеет).
- [ ] **Step 3: Commit** — `git commit -m "Run exits, an entry and the coordinator together in a lab test"`

### Task 15: Песочница и документация

**Files:**
- Modify: `ansibles/README.md`, `ansibles/PLAN.md`

Песочница — отдельная виртуалка владельца для экспериментов (адрес — в его личных инструкциях, не в репозитории): arm64, Oracle Linux 8, systemd, SELinux включён.

- [ ] **Step 1:** `scripts/build.sh`; `dist/ansibles init`; файл `targets.txt` с группой для хостера песочницы (сайты — с владельцем); `dist/ansibles alert set -token-file … -chat …` (бот и чат — от владельца).
  Expected: в Telegram пришло пробное сообщение.
- [ ] **Step 2:** `dist/ansibles node add -name lab1 -role exit -coordinator -addr АДРЕС -ssh ПОЛЬЗОВАТЕЛЬ@ПЕСОЧНИЦА -hoster ГРУППА`
  Expected: шаги по порядку без ошибок; `dist/ansibles status` показывает `lab1` с версией программы и картой 1. Если служба не стартует из-за SELinux (в журнале `avc: denied`), — в `node.sh.tmpl` после копирования программы `restorecon -R /opt/ansibles` при наличии команды, повторить; правку закоммитить с тестом на стенде `fakeHost`.
- [ ] **Step 3:** `dist/ansibles user add test` — Expected: за минуту `status` показывает у `lab1` список версии 2.
- [ ] **Step 4:** Собрать заведомо падающую программу (`main` сразу выходит с ошибкой), положить в `dist/`, `dist/ansibles upgrade` — Expected: откат на `lab1`, ошибка с его именем; `status` — прежняя версия, узел жив. Пересобрать нормальную, `upgrade` — Expected: новая версия.
- [ ] **Step 5:** README: раздел «Новая сеть (этап 1)» — команды `init`, `node add`, `user add`, `status`, `upgrade`, `alert set`, файлы `network.json`, `targets.txt` (формат строки), `dist/`; что нынешние узлы пока на `legacy`. PLAN.md: строка статуса «этап 1 сделан» с датой.
- [ ] **Step 6:** Run: `go test ./...` — Expected: PASS. Commit — `git commit -m "Document stage one of the self-steering network"`
