# Dynamic Firewall with Security Event Logger — Deliverable 1 (D1)

**Course:** Computer Networks · SDN + TCP Socket Programming Mini Project  
**Assigned topic:** Dynamic Firewall with Security Event Logger  
**Status:** D1 prototype; not the final D2 implementation.

## 1. Problem and objectives (D1: 2 marks)

Build a TCP client/server application inside a Mininet network controlled by
an SDN firewall. The firewall classifies traffic by source IP, destination IP,
and TCP port, and installs OpenFlow **allow** or **deny** rules. A simple TCP
application-event channel tells the controller when a client violates the
message protocol; the controller installs a source-host **block** rule. A
separate centralized TCP server logs security events.

## 2. Architecture

```text
        Mininet, Open vSwitch s1 (OpenFlow 1.3)
 h1 10.0.0.1 (client) ----|
 h3 10.0.0.3 (client) ----|-- s1 -- h2 10.0.0.2 (TCP server :5000)
 h4 10.0.0.4 (client) ----|   |
                              +-- ctl0 10.0.0.100 (host management interface)
                                   |-- Ryu controller: OpenFlow TCP :6653
                                   |-- Application report channel: TCP :9999
                                   +-- Central event logger: TCP :5514
```

| Component | File | Purpose |
|---|---|---|
| Client | `app/tcp_client.py` | Sends HELLO, MSG, BYE; optional malformed commands |
| Server | `app/tcp_server.py` | Multi-client/threaded TCP server; reports protocol violations |
| Controller | `controller/firewall_controller.py` | OpenFlow 1.3 policy, allow/deny, app-triggered host block |
| Logger | `logger/logger_server.py` | Collects controller + server JSON events over TCP |
| Topology | `topology/topo.py` | 4 hosts, 1 OVS switch, remote Ryu controller |
| D1 smoke tests | `tests/run_tests.py` | Verifies D1-only outcomes and saves test report |

**Application protocol:** line-delimited UTF-8 `HELLO <name>` → `OK welcome`;
`MSG <text>` → `ECHO <text>`; `BYE` → `OK bye`. Three unrecognized commands
cause the server to send `APP_VIOLATION` over TCP to the SDN controller.

**Firewall policy:** traffic to server `10.0.0.2` TCP port `5000` is ALLOWED;
TCP on other application ports (including `23`) is DENIED. TCP management
traffic to/from `10.0.0.100` is allowed so server reports can reach the
controller/logger. ARP and ICMP are forwarded for topology connectivity.
On `APP_VIOLATION`, the controller installs a higher-priority block rule for
the source client (removed only when the controller/switch is restarted in D1).

## 3. Prerequisites and setup

Use an **Ubuntu VM** with sudo access and network connectivity. Tested
with respect to source-code syntax and local TCP behavior; full Mininet demo
must be verified on the target Ubuntu VM.

From the extracted project directory:

```bash
chmod +x setup.sh run.sh
./setup.sh
```

`setup.sh` installs Mininet/Open vSwitch and creates `.venv` with Python 3.10
for Ryu. It needs internet access and may take several minutes.

## 4. Run and show D1

Use **three terminals**, all in the project root:

```bash
# Terminal 1
./run.sh logger

# Terminal 2
./run.sh controller

# Terminal 3 — automatic D1 tests (starts/stops Mininet)
./run.sh test
```

The output summary is written to `results/d1_test_results.txt`.
Check `logs/security_events.log` for ALLOW, DENY, APP_VIOLATION, and BLOCK
records. Do not claim a passing Mininet demo until the commands pass on the VM.

### Manual demonstration (alternative to automated tests)

Keep logger and controller running. In terminal 3:

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

To see the central event log, in a separate Ubuntu terminal:

```bash
cat logs/security_events.log
```

**Repeat tests:** The D1 block is intentionally persistent for this demo.
Restart the controller and create a fresh topology before rerunning an
application-violation test. If Mininet exited abnormally, run `sudo mn -c`.

## 5. D1 verification checklist (15 marks)

| D1 rubric item | Points | Evidence |
|---|---:|---|
| Problem understanding / architecture | 2 | This README and topology diagram |
| TCP sockets / multi-client | 4 | Client + threaded server; tests D1-2, D1-3 |
| Mininet + SDN | 4 | Topology, OpenFlow allow/deny; tests D1-1, D1-4 |
| Socket–SDN integration | 3 | APP_VIOLATION report causes block; test D1-5 |
| Initial testing / demo | 2 | Test runner and central event log; D1-1 to D1-6 |

## 6. Planned for D2 (not implemented in this D1-only ZIP)

Automatic attack-rate blocking, timed recovery/unblocking, advanced robustness
scenarios, blocking response-time measurements, network impact comparisons,
and larger performance evaluation. These are beyond the **D1** rubric.
