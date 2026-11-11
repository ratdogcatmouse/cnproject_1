# Dynamic Firewall with Security Event Logger

An SDN firewall (Ryu, OpenFlow 1.3) that classifies socket traffic by source,
destination and port, installs allow / deny / block rules, detects attacks
automatically, recovers blocked hosts on a timer, and reports every security
event to a centralized TCP logging server. Everything runs in Mininet.

---

## 1. Project requirements → implementation

| Requirement | Where |
|---|---|
| TCP client/server communication | `app/tcp_server.py` (threaded), `app/tcp_client.py` |
| Classify traffic by source, destination and port | `controller/policy.json` rules + `classify()` in the controller |
| Dynamic firewall rules from the SDN controller | ALLOW / DENY / BLOCK OpenFlow flows installed at packet-in time |
| Centralized security-event logger | `logger/logger_server.py` ← controller + app server over TCP |
| Multiple clients | thread per client, `--max-clients` limit; test T03 |
| Automatic blocking and recovery | port-scan, connection-flood and app-violation detection; block rule with hard timeout, escalating for repeat offenders; FlowRemoved → UNBLOCK |
| Measure blocking response time and network impact | `tests/benchmark.py` (dynamic vs static baseline) and timings in `tests/run_tests.py` |

## 2. Architecture

```text
             Mininet, Open vSwitch s1 (OpenFlow 1.3, priorities 0/10/100/150/200)
 h1 10.0.0.1  client (+ admin port 8080) --|
 h3 10.0.0.3  client ----------------------|
 h4 10.0.0.4  client / attacker -----------|-- s1 -- h2 10.0.0.2  TCP server :5000 (app)
 h5 10.0.0.5  untrusted host --------------|   |                  :8080 (admin) :23 (decoy)
                                               |
                                               +-- ctl0 10.0.0.100 (root namespace)
                                                     |-- Ryu controller   OpenFlow :6653
                                                     |-- control channel  TCP :9999
                                                     +-- security logger  TCP :5514
```

| Component | File | Role |
|---|---|---|
| App server | `app/tcp_server.py` | Line protocol, thread per client, overload limit, reports violations to the controller, streams events to the logger |
| Client | `app/tcp_client.py` | Normal sessions, malformed sessions, `--probe` latency measurement |
| Attacker | `app/attacker.py` | Connection flood and TCP port scan for robustness tests |
| Controller | `controller/firewall_controller.py` | Policy classification, flow rules, attack detection, block / recovery, control channel |
| Policy | `controller/policy.json` | Rules, mode, detection thresholds, block timing |
| Logger | `logger/logger_server.py` | Central JSON-lines log → `logs/security_events.log` |
| Topology | `topology/topo.py` | 5 hosts, 1 OVS switch, remote controller, optional bandwidth shaping |
| Admin tool | `tools/fwctl.py` | `status`, `reset`, `mode static/dynamic`, `unblock IP` |
| Tests | `tests/run_tests.py` | 14 functional + robustness tests |
| Benchmark | `tests/benchmark.py` | Performance comparison against the static baseline |

### Communication flow

1. **New TCP connection.** The first packet misses all flows and goes to the controller (packet-in).
   The controller classifies (src, dst, dport) against `policy.json`.
2. **ALLOW.** It installs forward and reverse flows (priority 100, 30 s idle) and logs `ALLOW`.
   Later packets stay in the switch.
3. **DENY.** It installs a drop flow for that 5-tuple (priority 150, 5 s idle) and logs `DENY` with the matching rule.
4. **App violation.** After 3 malformed commands the server sends `APP_VIOLATION` over TCP to the
   controller (port 9999). The controller installs a **BLOCK** for that source (priority 200, drops all of its IPv4).
5. **Network attack.** The controller counts new flows per source. A port scan (≥ 5 distinct denied
   ports in 5 s) or a connection flood (≥ 40 new connections in 2 s) triggers a BLOCK.
6. **Recovery.** The block rule has a hard timeout (10 s, doubled for each repeat offence, max 120 s).
   The switch removes it and sends `FlowRemoved`, and the controller logs `UNBLOCK`.
7. **Logging.** The controller and the server each keep one persistent TCP connection to the logger
   and stream JSON events (`ALLOW`, `DENY`, `BLOCK`, `UNBLOCK`, `APP_VIOLATION`, `CLIENT_CONNECT`, ...).

### Application protocol (TCP :5000, UTF-8 lines)

`HELLO <name>` → `OK welcome <name>` · `MSG <text>` → `ECHO <text>` · `BYE` → `OK bye`.
Unknown commands and lines over 4096 bytes count as violations (`ERR unknown command`).
When `--max-clients` (100) sessions are active, new connections get `ERR busy`.

### Firewall policy (`controller/policy.json`)

Rules are checked top to bottom and the first match wins. Missing fields mean "any". The default is deny.

| Rule | Match | Action |
|---|---|---|
| untrusted-host | src 10.0.0.5 | deny |
| app-service | dst 10.0.0.2, dport 5000 | allow |
| admin-service-h1-only | src 10.0.0.1, dst 10.0.0.2, dport 8080 | allow |
| (default) | everything else, e.g. port 23 | deny |

Hosts may reach the management IP (10.0.0.100) **only on TCP 9999 (control channel) and 5514 (logger)**, and
receive replies from those ports; any other traffic to or from it follows the normal rules (default deny).
New connections to those ports count toward flood detection, except from the app server. Reply packets (non-SYN) of an allowed
connection are allowed. `mode` is `dynamic` (detection + blocking) or `static`, which uses the same
allow/deny rules and never blocks; it is the baseline for the benchmark.

### Control channel (TCP :9999, one JSON line in, one out)

| Message | Accepted from |
|---|---|
| `{"event":"APP_VIOLATION","src":ip,...}` | app server (10.0.0.2) only; anything else is logged as `REJECTED_REPORT` |
| `{"cmd":"STATUS" / "RESET" / "MODE" / "UNBLOCK"}` | localhost only; anything else is logged as `REJECTED_COMMAND` |

`src` must be a valid IPv4 address (otherwise an error reply). The channel has a 5 s socket timeout and at most
32 concurrent connections. The logger allows 8 connections per source IP (64 total) and closes connections
that send nothing within 10 s; non-object JSON lines are stored as `RAW` events.

## 3. Setup (Ubuntu 22.04 / 24.04 VM, sudo)

> The full system needs Linux (Mininet + Open vSwitch). On macOS use an Ubuntu VM (e.g. UTM or Multipass).
> Only the logger and the plain TCP server/client run natively on a Mac, e.g.
> `python3 app/tcp_server.py --controller 127.0.0.1 --logger 127.0.0.1` and `python3 app/tcp_client.py 127.0.0.1 5000`.

```bash
chmod +x setup.sh run.sh
./setup.sh
```

This installs Mininet and Open vSwitch, then creates `.venv` with Python 3.10 and Ryu 4.34 (Ryu does
not run on Python 3.12+). It needs internet access and takes a few minutes.

## 4. Running

Open **three terminals** in the project folder.

```bash
./run.sh logger        # terminal 1: central security logger
./run.sh controller    # terminal 2: Ryu firewall controller
./run.sh test          # terminal 3: 14 automated tests (~1.5 min)
./run.sh bench         # terminal 3: performance evaluation (~2.5 min)
```

- Test report: `results/test_results.txt`
- Benchmark: `results/benchmark.md` and `results/benchmark.csv` (`./run.sh bench --repeat 3` for more runs)
- Security log: `logs/security_events.log` (`tail -f` it during a demo)

Both scripts start and stop Mininet themselves and reset the controller before each experiment.
The logger and controller can stay running.

### Manual demonstration

With the logger and controller running, start the topology (optionally `--bw 10` for 10 Mbit/s links):

```bash
./run.sh topo
```

At the `mininet>` prompt:

```text
pingall
h2 python3 app/tcp_server.py --port 5000 > logs/server_5000.out 2>&1 &
h2 python3 app/tcp_server.py --port 8080 > logs/server_8080.out 2>&1 &
h2 python3 app/tcp_server.py --port 23   > logs/server_23.out 2>&1 &

h1 python3 app/tcp_client.py 10.0.0.2 5000 --msgs 3      # ALLOW
h1 python3 app/tcp_client.py 10.0.0.2 8080               # ALLOW (8080 is h1-only)
h3 python3 app/tcp_client.py 10.0.0.2 8080               # DENY  (source rule)
h5 python3 app/tcp_client.py 10.0.0.2 5000               # DENY  (untrusted host)
h4 python3 app/tcp_client.py 10.0.0.2 23                 # DENY  (port rule)

h3 python3 app/tcp_client.py 10.0.0.2 5000 --bad 3       # APP_VIOLATION -> h3 blocked 10 s
h3 python3 app/tcp_client.py 10.0.0.2 5000               # fails now; works again after 10 s

h4 python3 app/attacker.py scan 10.0.0.2 --ports 4980-5020        # PORT_SCAN -> h4 blocked
h1 python3 app/tcp_client.py 10.0.0.2 5000 --probe 5              # legit user unaffected
sh ovs-ofctl -O OpenFlow13 dump-flows s1                          # see priority=200 block rules
```

Admin commands, from another terminal:

```bash
./run.sh ctl status                 # mode, blocked hosts + seconds left, block history
./run.sh ctl unblock 10.0.0.4       # manual recovery
./run.sh ctl mode static            # switch to the static baseline (and back: mode dynamic)
./run.sh ctl reset                  # clear all flows, blocks and offence counters
```

To show a connection flood, wait for h4's block to expire (or `ctl unblock`), then run
`h4 python3 app/attacker.py flood 10.0.0.2 5000 --seconds 4`. Its second block lasts 20 s (escalation).
Type `exit` to leave Mininet.

## 5. Test cases (`tests/run_tests.py`)

| # | Test | Shows |
|---|---|---|
| T01 | pingall across 5 hosts | Topology and L2 forwarding |
| T02 | h1 ↔ server on :5000 | TCP application exchange |
| T03 | h1, h3 and h4 sessions at the same time | Concurrent clients |
| T04 | :8080 allowed for h1, denied for h3 | Source-based classification |
| T05 | h5 denied on :5000 | Untrusted-host rule |
| T06 | :23 denied although the server listens | Destination-port rule |
| T07 | 3 bad commands from h3 → h3 blocked, h1 still works | Socket event → SDN block |
| T08 | h3 can connect again after 10 s | Automatic recovery (FlowRemoved → UNBLOCK) |
| T09 | h4 port scan → blocked before reaching :5000 | Unauthorized-access scenario |
| T10 | h4 connection flood → blocked, h1 still works | Flood / overload scenario |
| T11 | Second offence → 20 s block | Escalation |
| T12 | Admin command and forged report from h1 rejected | Control-channel security |
| T13 | Static mode lets the flood through | Baseline behaviour |
| T14 | Log has controller + server events of all kinds | Central logger |

## 6. Performance evaluation (`tests/benchmark.py`)

**Method.** Links are 10 Mbit/s. For each scenario, both static and dynamic: legitimate client h1
runs a 12 s probe (one full HELLO/MSG/BYE session every 0.2 s, each a new TCP connection through
the controller). Attacker h4 attacks for 8 s starting at t = 2 s.

**Metrics.** Legitimate success rate, average and p95 session latency, attack sessions served (or
services discovered by the scan), **blocking response time** (attack start → block rule installed)
and time until attack traffic stopped getting through.

**Reference run.** From the development environment (userspace Open vSwitch); your VM's numbers will differ:

| Mode | Scenario | Legit OK % | Avg ms | p95 ms | Attack served | Block response | Attack stopped after |
|---|---|---|---|---|---|---|---|
| static | no attack | 100 | 6.35 | 9.14 | – | – | – |
| dynamic | no attack | 100 | 5.92 | 8.87 | – | – | – |
| static | flood 50 conn/s | 100 | 6.61 | 10.13 | 400 | never | never |
| dynamic | flood 50 conn/s | 100 | 6.18 | 8.98 | 39 | 727.5 ms | 730.3 ms |
| static | flood max rate | 100 | 40.36 | 80.76 | 3691 | never | never |
| dynamic | flood max rate | 100 | 8.21 | 12.01 | 34 | 109.0 ms | 108.9 ms |
| static | port scan | 100 | 5.94 | 7.92 | open ports [5000] | never | never |
| dynamic | port scan | 100 | 5.96 | 8.36 | open ports [] | 505.7 ms | none got through |

Timings from `run_tests.py`: APP_VIOLATION report → block rule **8–11 ms**; connection flood →
block **68–86 ms**; recovery after **10.1 s** (configured 10 s timeout).

**Interpretation.**
- Dynamic mode adds no measurable overhead without an attack (5.9 vs 6.4 ms).
- Under a full-rate flood, the static firewall serves ~3,700 attack sessions and legitimate latency
  rises about 6× (p95 81 ms). The dynamic firewall blocks the attacker in ~0.1 s, serves only ~34
  attack sessions and keeps latency near baseline.
- A slower flood (50 conn/s) needs ~0.7 s to cross the 40-connections-in-2-s threshold, so the response time depends on attack rate and the threshold.
- The scan's response time (~0.5 s) is set by the scanner: the 5th distinct denied port
  arrives only after the first probes time out. The block lands before the scan reaches :5000, so
  the service is never discovered. The static firewall lets it be found.

## 7. Rubric mapping

| Component | Marks | Evidence |
|---|---:|---|
| D1: Problem understanding and architecture | 2 | Sections 1–2 |
| D1: TCP socket implementation | 4 | Threaded server, protocol, error handling, client; T02–T03 |
| D1: Mininet + SDN implementation | 4 | Topology, OpenFlow 1.3 policy flows; T01, T04–T06 |
| D1: Socket–SDN integration | 3 | App server → controller reports → block; T07 |
| D1: Initial testing and demo | 2 | `run_tests.py`, manual demo |
| D2: Complete application functionality | 4 | All project bullets (section 1); T01–T08, T14 |
| D2: Dynamic SDN functionality | 6 | Packet-in monitoring, filtering, automatic blocking, timed recovery, escalation, runtime mode switch; T07–T11 |
| D2: Challenging scenario / robustness | 4 | Port scan, connection flood, server overload limit, forged control messages; T09–T13 |
| D2: Performance evaluation and comparison | 5 | `benchmark.py`: 4 scenarios × static/dynamic, latency, success, response time |
| D2: Documentation, demo, viva | 6 | This README, scripts, reproducible tests |

## 8. Troubleshooting

- **Mininet left over from a crash:** `sudo mn -c`
- **"Start ./run.sh logger / controller first":** both must be running before `test`, `bench` or `topo`.
- **Address already in use (5514 / 6653 / 9999):** an old logger or controller is still running; stop it with Ctrl+C or `pkill -f ryu-manager`.
- **No Open vSwitch kernel module (some containers/VMs):** run with `FW_DATAPATH=user`, e.g.
  `sudo FW_DATAPATH=user python3 tests/run_tests.py`. The topology then turns off checksum
  offload, which userspace OVS needs for TCP.
- **Ryu install fails:** Ryu needs Python ≤ 3.10; `setup.sh` creates a separate 3.10 environment with `uv`.

## 9. Limitations

- Detection only sees new flows that reach the controller. A flood on a single long-lived connection
  stays in the switch and is not counted; flow-statistics polling would be the next step.
- An attacker below the thresholds (e.g. < 20 conn/s) is not blocked; thresholds are a trade-off
  against false positives and are set in `policy.json`.
- Only TCP is filtered. ARP, ICMP, UDP and other IP traffic are forwarded without policy checks (and UDP is not
  covered by detection).
- Source IPs are not authenticated (no anti-spoofing / IP-MAC binding).
- The firewall is stateless per packet (reply traffic is recognised by the reverse rule match), and
  the policy is for a single switch.

## 10. Contributions

| Member | Area | Main rubric items |
|---|---|---|
| **Hrishikesh Das** | TCP application | Complete application functionality
| **Ishaan Bhatia** | Mininet topology and SDN controller | Dynamic SDN functionality
| **Hemadarshini** | Security logger, testing and evaluation | Performance evaluation, documentation

### Hrishikesh Das: TCP application (~415 lines)

- `app/common.py`
- `app/tcp_server.py`
- `app/tcp_client.py`
- `app/attacker.py`

### Ishaan Bhatia: Mininet topology and SDN controller (~430 lines)

- `topology/topo.py`
- `controller/firewall_controller.py`
- `controller/policy.json`

### Hemadarshni: Security logger, testing and evaluation (~555 lines)

- `logger/`
- `tools/fwctl.py`
- `tests/lab.py`, `tests/run_tests.py`, `tests/benchmark.py`
- `run.sh`, `setup.sh`
- `README.md`
