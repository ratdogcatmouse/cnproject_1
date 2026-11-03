# Dynamic Firewall with Security Event Logger

**Course:** Computer Networks · SDN + TCP Socket Programming Mini Project
**Status:** D1 prototype. Automatic attack-rate blocking, timed unblocking and performance evaluation are planned for D2 (see [Roadmap](#9-roadmap-d2)).

## 1. Overview

This project combines **Software-Defined Networking** with **TCP socket programming** to build a firewall that reacts to what applications are doing, not just to what packets look like.

A [Mininet](http://mininet.org/) network of four hosts hangs off one Open vSwitch switch. The switch is controlled by a [Ryu](https://ryu-sdn.org/) OpenFlow 1.3 controller that classifies TCP traffic by source IP, destination IP and TCP port, and installs **allow**, **deny** or **block** flow rules. A threaded TCP application server runs on one host. When a client breaks the application protocol, the server reports it to the controller over a TCP side channel, and the controller blocks that client at the switch. A separate centralized TCP logger records every security decision as a JSON event.

## 2. Objectives

1. **Network-level filtering.** Allow or deny TCP flows by IP and port using OpenFlow rules installed reactively by the controller.
2. **Application-aware blocking.** Close the loop between the socket layer and the SDN control plane. A protocol violation seen by the server triggers a switch-level block of the offending host.
3. **Multi-client TCP service.** Provide a threaded, line-based client/server application that handles concurrent clients.
4. **Centralized security logging.** Collect ALLOW, DENY, APP_VIOLATION and BLOCK events from both the controller and the server in one auditable log.
5. **Reproducible verification.** Provide an automated test runner that builds the topology, exercises each behaviour and writes a pass/fail report.

## 3. Functionality

### 3.1 Firewall policy

| Traffic | Decision |
|---|---|
| TCP to server `10.0.0.2` port `5000` (and the server's replies) | **ALLOW** |
| TCP to/from the management address `10.0.0.100` | **ALLOW** (so server reports reach the controller and logger) |
| TCP to any other destination or port (for example `23`) | **DENY** |
| ARP and ICMP | Forwarded at layer 2 for connectivity |
| Any IP traffic from a host reported for a protocol violation | **BLOCK** (all traffic dropped) |

### 3.2 Application protocol

Line-delimited UTF-8 over TCP:

| Client sends | Server replies |
|---|---|
| `HELLO <name>` | `OK welcome <name>` |
| `MSG <text>` | `ECHO <text>` |
| `BYE` | `OK bye`, then closes |
| anything else | `ERR unknown command` and the violation counter for that IP increments |

After **3** unrecognized commands from one client IP (configurable with `--violations`), the server sends an `APP_VIOLATION` JSON line to the controller on TCP `:9999` and closes the connection.

### 3.3 Security events

Events are JSON lines appended to `logs/security_events.log`.

| Event | Source | Meaning |
|---|---|---|
| `SWITCH_CONNECTED` | controller | Switch handshake complete; table-miss rule installed |
| `ALLOW` | controller | A new permitted TCP connection (logged on SYN) |
| `DENY` | controller | A TCP flow was denied by policy |
| `CLIENT_CONNECT` / `CLIENT_DISCONNECT` | app-server | Connection lifecycle |
| `BAD_COMMAND` | app-server | One protocol violation, with running count |
| `APP_VIOLATION` | controller | Violation report received from the server |
| `BLOCK` | controller | Block rule installed for the offending source IP |

The logger adds `logger_ts` and `from` fields to each record.

## 4. Architecture and design

### 4.1 Topology

```text
        Mininet, Open vSwitch s1 (OpenFlow 1.3)
 h1 10.0.0.1 (client) ----|
 h3 10.0.0.3 (client) ----|-- s1 -- h2 10.0.0.2 (TCP server :5000)
 h4 10.0.0.4 (client) ----|   |
                              +-- ctl0 10.0.0.100 (internal port, root namespace)
                                   |-- Ryu controller: OpenFlow TCP :6653
                                   |-- Application report channel: TCP :9999
                                   +-- Central event logger: TCP :5514
```

The controller and logger run in the root namespace, outside Mininet. The topology adds an OVS internal port, `ctl0`, to `s1` and gives it `10.0.0.100`. Hosts reach the controller and logger through this port, so the application traffic and the control/logging traffic share one data plane and go through the same firewall.

### 4.2 Components

| Component | File | Responsibility |
|---|---|---|
| Client | [app/tcp_client.py](app/tcp_client.py) | Sends HELLO/MSG/BYE; `--bad N` sends malformed commands; prints `RESULT OK/FAIL` |
| Server | [app/tcp_server.py](app/tcp_server.py) | Thread-per-client server; counts violations per IP; reports to the controller; logs events |
| Shared constants | [app/common.py](app/common.py) | Ports, management IP, timestamp helper, `send_json` |
| Controller | [controller/firewall_controller.py](controller/firewall_controller.py) | Ryu app: MAC learning, TCP classification, flow installation, report channel, blocking |
| Logger | [logger/logger_server.py](logger/logger_server.py) | Thread-per-connection TCP server appending JSON events to a file |
| Topology | [topology/topo.py](topology/topo.py) | 4 hosts, 1 OVS switch, remote controller, `ctl0` management port |
| Tests | [tests/run_tests.py](tests/run_tests.py) | Automated D1 test run; writes `results/d1_test_results.txt` |

### 4.3 Network ports

| Port | Used by | Purpose |
|---|---|---|
| 6653 | Ryu | OpenFlow channel from the switch |
| 9999 | Ryu | Application violation reports from the server |
| 5514 | Logger | Event ingestion |
| 5000 | App server | Permitted application service |
| 23 | App server (test only) | Listener used to show that the firewall, not a missing service, refuses the connection |

### 4.4 Controller design

The controller is reactive. A table-miss rule (priority 0) sends unmatched packets to the controller, which decides what to install.

| Priority | Rule | Timeout |
|---|---|---|
| 0 | Table miss: send to controller | none |
| 10 | L2 forwarding for ARP/ICMP | idle 20 s |
| 100 | **ALLOW**: exact TCP 5-tuple, forward and reverse | idle 30 s |
| 150 | **DENY**: exact TCP 5-tuple, drop | idle 5 s |
| 200 | **BLOCK**: all IPv4 from the source IP, drop | permanent (D1) |

Packet-in handling:

1. Learn `src MAC → in_port`; look up the output port for the destination MAC, or flood.
2. For TCP packets, drop silently if the source is already in the `blocked` set. Otherwise call `classify()`. A `DENY` installs a drop flow and logs the event. An `ALLOW` installs forward and reverse flows, re-injects the packet with a packet-out, and logs the connection on SYN.
3. ARP and ICMP get layer-2 flows only. Generic IP layer-2 flows are deliberately not cached, because they would bypass the TCP rules.

Priorities make the policy compose correctly. A block (200) overrides a deny (150), which overrides an allow (100), which overrides plain forwarding (10).

### 4.5 Event flow: application violation to switch block

```text
 h3 client            h2 server               Ryu controller         s1 switch        Logger
    | HELLO, BOGUS x3     |                         |                    |               |
    |-------------------->| count violations (3)    |                    |               |
    |                     |-- APP_VIOLATION (:9999) >|                    |               |
    |                     |                         |-- FlowMod prio 200 >|              |
    |                     |                         |   (drop ipv4_src=h3)               |
    |                     |-- BAD_COMMAND events ---------------------------------------->|
    |                     |                         |-- APP_VIOLATION, BLOCK ----------->|
    | all further IP traffic from h3 is dropped at s1                                     |
```

### 4.6 Design decisions

- **Two-layer enforcement.** The switch enforces network-level policy at line rate. The server detects application-level misbehaviour that packet headers cannot reveal, and the controller turns that signal into a network rule.
- **Short-lived JSON-line messages.** Reports and log events each use one short TCP connection carrying one JSON line. This keeps senders simple and lets any component fail independently. If the logger is down, the controller warns and keeps working.
- **Management traffic through the data plane.** Routing reports through `ctl0` means block and deny rules apply uniformly, with no out-of-band path.
- **Short deny timeouts.** Denied flows expire after 5 s idle, so the controller re-evaluates policy rather than holding stale state.
- **Exact-match flows.** Each rule matches a full TCP 5-tuple, which keeps decisions auditable per connection at the cost of more packet-ins.

## 5. Prerequisites and setup

An **Ubuntu VM** with sudo and internet access is required. Mininet and Open vSwitch do not run on macOS.

```bash
chmod +x setup.sh run.sh
./setup.sh
```

`setup.sh` installs Mininet and Open vSwitch with apt, then builds a Python 3.10 `.venv` (via `uv`) for Ryu. Ryu does not work on Python 3.12 or newer. It pins `eventlet==0.33.3` and `dnspython==2.2.1` and patches Ryu's `wsgi.py` for eventlet compatibility. The Mininet scripts use the system Python.

## 6. Running

Use **three terminals**, all in the project root.

```bash
# Terminal 1
./run.sh logger

# Terminal 2
./run.sh controller

# Terminal 3: automated tests (starts and stops Mininet)
./run.sh test
```

The test summary is written to `results/d1_test_results.txt`. Events are in `logs/security_events.log`.

### 6.1 Manual demonstration

With the logger and controller running, in terminal 3:

```bash
./run.sh topo
```

At the `mininet>` prompt:

```text
pingall
h2 python3 app/tcp_server.py --port 5000 &
h2 python3 app/tcp_server.py --port 23 &
h1 python3 app/tcp_client.py 10.0.0.2 5000 --msgs 3
h4 python3 app/tcp_client.py 10.0.0.2 23 --timeout 2
h3 python3 app/tcp_client.py 10.0.0.2 5000 --bad 3
sh ovs-ofctl -O OpenFlow13 dump-flows s1
```

Expected results: the `h1` call succeeds, the `h4` call fails (denied), the `h3` call sends its malformed commands, and then `h3` is blocked. The flow dump shows a `priority=200` drop rule for `10.0.0.3`. Then inspect `cat logs/security_events.log`.

### 6.2 Command reference

| Command | Effect |
|---|---|
| `./run.sh logger` | Start the central logger on TCP 5514 |
| `./run.sh controller` | Start the Ryu controller (OpenFlow 6653, reports 9999) |
| `./run.sh topo` | Open the interactive Mininet CLI |
| `./run.sh test` | Run the automated tests (uses sudo) |
| `sudo mn -c` | Clean up after an abnormal Mininet exit |

**Re-running tests:** blocks persist in D1 and are cleared only when the switch reconnects. Restart the controller and create a fresh topology before repeating the violation test.

## 7. Tests

`tests/run_tests.py` builds the topology and checks:

| ID | Check |
|---|---|
| D1-1 | All hosts reach each other (0% ping loss) |
| D1-2 | A client completes an allowed exchange on port 5000 |
| D1-3 | Two clients (h1, h3) use the server concurrently |
| D1-4 | Port 23 is denied and a `DENY` event is logged |
| D1-5 | Three bad commands produce `APP_VIOLATION`, `BLOCK`, and a `priority=200` flow |
| D1-6 | The logger received events from both the controller and the app server |

The tests read `logs/security_events.log`, so the logger must be running.

## 8. Project layout

```text
sdn-firewall-project/
├── app/            tcp_client.py, tcp_server.py, common.py
├── controller/     firewall_controller.py   (Ryu app)
├── logger/         logger_server.py
├── topology/       topo.py                  (Mininet)
├── tests/          run_tests.py
├── logs/           security_events.log      (generated)
├── results/        d1_test_results.txt      (generated)
├── setup.sh        one-time installation
├── run.sh          launcher
└── requirements.txt
```

