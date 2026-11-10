# Live security dashboard

An **optional, additive** web dashboard for the SDN dynamic firewall. It lives
entirely in this folder: no existing project file is modified or imported.

It shows, live:

- network topology (h1–h5, switch, controller) with blocked hosts in red and a countdown to automatic recovery
- counters: allowed / denied flows, blocks, recoveries, app violations, rejected control messages
- traffic over the last 60 seconds, with a marker whenever a block is installed
- currently blocked hosts (reason, offence number, time left) and a block history
- a colour-coded, filterable event feed (Allow, Deny, Block/Unblock, Alerts)
- the firewall mode (dynamic / static) as a button you can click during the demo
- **plain-language pop-ups** that explain what is happening (who is trying what, which rule applies, what is allowed or denied); the host involved gets a coloured ring in the topology

## Run it (live)

Start the usual services first, then the dashboard, then open the page in the
VM's browser:

```bash
./run.sh logger          # terminal 1
./run.sh controller      # terminal 2
python3 dashboard/server.py        # terminal 3  ->  http://127.0.0.1:8000
./run.sh topo            # terminal 4, then run the demo commands (README section 4)
```

Also works while `./run.sh test` or `./run.sh bench` is running. Python 3 only,
nothing to install. Options: `--port 8001`, `--fresh` (ignore events already in
the log), `--log PATH`.

## Run it without Mininet (narrated demo)

```bash
python3 dashboard/server.py --demo              # slow, narrated (about 3 minutes per loop)
python3 dashboard/server.py --demo --speed 2    # twice as fast
```

A guided walk-through with a pop-up for every step. It uses the same event
format as the real controller, so it doubles as a safety net if the network
misbehaves during a presentation.

| Scene | What happens | What the pop-up explains |
|---|---|---|
| Intro | five hosts, one app server | the policy: what is allowed, what is denied |
| 1 | h1, h3, h4 use port 5000 | ALLOW by rule `app-service` |
| 2 | h5 tries port 5000 | DENY by rule `untrusted-host` (checked first) |
| 3 | h4 tries port 23 | DENY by the default policy |
| 4 | h1 and h3 try admin port 8080 | source-based rule: h1 allowed, h3 denied |
| 5 | h3 sends malformed commands | app server reports, controller blocks h3, automatic recovery |
| 6 | h4 scans ports | port scan detected after 5 denied ports, blocked, recovers |
| 7 | h4 floods the server | flood detected, second offence = block time doubles |
| 8 | h1 forges a report / admin command | both rejected, firewall unaffected |

Controls in the page header:

- **Pause demo / Resume demo**: freezes the story, the block timers and the pop-up so you can talk over it.
- **Pop-ups ON/OFF**: hide the explanations if you only want the numbers.
- **Mode: DYNAMIC / STATIC**: click it mid-demo. In static mode the same attacks are *not* blocked and the pop-ups say so, which shows why the dynamic mode matters.

In live mode (real controller) the pop-ups appear automatically for the important
events: a host being blocked, recovering, a rejected forged report or admin
command, and a mode change.

## How it works

- It follows `logs/security_events.log` (the central logger's output) and
  survives the file being truncated by `tests/run_tests.py`.
- Once per second it sends `STATUS` to the controller's existing control
  channel (`127.0.0.1:9999`, localhost only) for the mode and blocked hosts.
- The buttons (mode switch, Unblock, Reset firewall) use the same control
  channel commands as `tools/fwctl.py`. Nothing else is exposed.
- The server listens on `127.0.0.1` only by default. State-changing requests
  need a custom header, so other web pages cannot trigger them.

## Troubleshooting

- **Red banner "Controller control channel not reachable"**: start `./run.sh controller`. The feed still follows the log.
- **Empty feed**: nothing has happened yet; run `./run.sh test` or `./run.sh topo`.
- **Pop-ups cover the counters**: close one with ×, or switch them off with *Pop-ups: ON*.
- **Counters look wrong after a restart**: press *Clear view*, or start with `--fresh`.
- **Port already in use**: `python3 dashboard/server.py --port 8001`.
