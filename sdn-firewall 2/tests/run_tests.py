#!/usr/bin/env python3
"""Functional + robustness tests in Mininet.  Start the logger and Ryu first.

    sudo python3 tests/run_tests.py      ->  results/test_results.txt
"""
import json
import os
import time

from mininet.log import setLogLevel

from lab import (APP, DETECTION, LOG, RESULTS, ROOT, SERVER, attack_cmd, block_for,
                 client, create_network, ctl, log_events, require_services,
                 start_servers, stop_servers, tagged, wait)

results, timings = [], []


def check(label, passed, detail=""):
    results.append((label, bool(passed), detail))
    print("[%s] %s %s" % ("PASS" if passed else "FAIL", label, detail), flush=True)


def ok(output):
    return "RESULT OK" in output


def unblock_logged(src, since):
    return next((e for e in log_events() if e.get("event") == "UNBLOCK" and
                 e.get("src") == src and e.get("epoch", 0) >= since), None)


def run(net):
    h1, h2, h3, h4, h5 = (net.get("h%d" % n) for n in range(1, 6))
    base = DETECTION["block_seconds"]

    net.pingAll(timeout=1)                    # ARP / MAC learning warm-up
    loss = net.pingAll(timeout=1)
    check("T01 Mininet connectivity (5 hosts, ICMP)", loss == 0, "loss=%s%%" % loss)

    start_servers(h2)
    out = client(h1, "%s 5000 --name h1 --msgs 3" % SERVER)
    check("T02 Allowed TCP application exchange", ok(out), out)

    for h in (h1, h3, h4):
        h.sendCmd("python3 %s/tcp_client.py %s 5000 --name %s --msgs 20 --delay 0.05"
                  % (APP, SERVER, h.name))
    outs = [h.waitOutput() for h in (h1, h3, h4)]
    check("T03 Three concurrent TCP clients", all(ok(o) for o in outs))

    a, b = client(h1, "%s 8080 --name h1" % SERVER), client(h3, "%s 8080 --name h3" % SERVER)
    check("T04 Source-based rule: 8080 allowed for h1 only", ok(a) and not ok(b),
          "h1=%s | h3=%s" % (a, b))

    out = client(h5, "%s 5000 --name h5" % SERVER)
    denied = wait(lambda: any(e.get("event") == "DENY" and e.get("src") == "10.0.0.5" and
                              e.get("rule") == "untrusted-host" for e in log_events()), 3)
    check("T05 Untrusted host h5 denied by source rule", not ok(out) and denied, out)

    out = client(h4, "%s 23 --name h4" % SERVER)
    check("T06 Port 23 denied (server is listening)", not ok(out), out)

    # --- application event -> SDN block -> automatic recovery ---------------
    t0 = time.time()
    out = client(h3, "%s 5000 --name h3 --bad 3" % SERVER)
    rec = wait(lambda: block_for("10.0.0.3", t0, "APP_VIOLATION"), 5)
    during = client(h3, "%s 5000 --name h3 --timeout 1" % SERVER)
    other = client(h1, "%s 5000 --name h1" % SERVER)
    react = (rec["blocked_at"] - rec["first_seen"]) * 1000 if rec else None
    check("T07 App violation report blocks h3 (h1 unaffected)",
          ok(out) and rec and not ok(during) and ok(other),
          "reaction=%.1f ms" % react if rec else "no block")
    if rec:
        timings.append(("APP_VIOLATION report -> block rule", "%.1f ms" % react))
        unb = wait(lambda: unblock_logged("10.0.0.3", t0), base + 6)
        back = client(h3, "%s 5000 --name h3" % SERVER) if unb else ""
        check("T08 Automatic recovery after %ss hard timeout" % base,
              unb and unb.get("reason") == "timeout" and ok(back),
              "blocked_for=%ss" % (unb or {}).get("blocked_for"))
        if unb:
            timings.append(("block duration until recovery", "%.2f s" % unb["blocked_for"]))
    else:
        check("T08 Automatic recovery", False, "no block to recover from")

    # --- port scan -----------------------------------------------------------
    ctl("RESET")
    time.sleep(1)
    summary = tagged(h4.cmd(attack_cmd("scan %s --ports 4980-5020 --workers 4 --seconds 6"
                                       % SERVER)), "ATTACK")
    rec = block_for("10.0.0.4", summary["start"], "PORT_SCAN")
    resp = (rec["blocked_at"] - summary["start"]) * 1000 if rec else None
    check("T09 Port scan detected and blocked before finding :5000",
          rec and 5000 not in summary["open"],
          "response=%.1f ms, open=%s, probed=%d" % (resp, summary["open"], summary["probed"])
          if rec else "no block, open=%s" % summary["open"])
    if rec:
        timings.append(("port scan start -> block rule", "%.1f ms" % resp))

    # --- connection flood -----------------------------------------------------
    ctl("RESET")
    time.sleep(1)
    summary = tagged(h4.cmd(attack_cmd("flood %s 5000 --seconds 4 --workers 8" % SERVER)),
                     "ATTACK")
    rec = block_for("10.0.0.4", summary["start"], "CONN_FLOOD")
    other = client(h1, "%s 5000 --name h1" % SERVER)
    resp = (rec["blocked_at"] - summary["start"]) * 1000 if rec else None
    check("T10 Connection flood detected and blocked (h1 unaffected)", rec and ok(other),
          "response=%.1f ms, attack sessions served=%d" % (resp, summary["ok"])
          if rec else "no block")
    if rec:
        timings.append(("connection flood start -> block rule", "%.1f ms" % resp))

    ctl("UNBLOCK", src="10.0.0.4")
    time.sleep(1)
    t0 = time.time()
    h4.cmd(attack_cmd("flood %s 5000 --seconds 3 --workers 8" % SERVER))
    rec = block_for("10.0.0.4", t0, "CONN_FLOOD")
    check("T11 Repeat offender gets escalated block time",
          rec and rec["offence"] == 2 and rec["seconds"] == min(2 * base, DETECTION["block_max"]),
          "offence=%s seconds=%s" % (rec["offence"], rec["seconds"]) if rec else "no block")

    # --- control channel security -----------------------------------------------
    ctl("RESET")
    out = h1.cmd("python3 %s/tools/fwctl.py --host 10.0.0.100 mode static" % ROOT)
    forged = h1.cmd("python3 -c \"import sys; sys.path.insert(0, '%s'); from common import "
                    "request; print(request('10.0.0.100', 9999, {'event': 'APP_VIOLATION', "
                    "'src': '10.0.0.3'}))\"" % APP)
    status = ctl("STATUS")
    check("T12 Control channel rejects hosts (admin cmd + forged report)",
          "only from localhost" in out and "only from the app server" in forged
          and status["mode"] == "dynamic"
          and "10.0.0.3" not in status["blocked"])

    # --- static baseline -----------------------------------------------------------
    ctl("MODE", mode="static")
    ctl("RESET")
    time.sleep(1)
    summary = tagged(h4.cmd(attack_cmd("flood %s 5000 --seconds 3 --workers 8" % SERVER)),
                     "ATTACK")
    check("T13 Static mode (baseline) never blocks the flood",
          not block_for("10.0.0.4", summary["start"]) and summary["ok"] > 0,
          "attack sessions served=%d" % summary["ok"])
    ctl("MODE", mode="dynamic")
    ctl("RESET")

    time.sleep(1)
    events = log_events()
    kinds = {e.get("event") for e in events}
    need = {"ALLOW", "DENY", "BLOCK", "UNBLOCK", "APP_VIOLATION", "REJECTED_COMMAND",
            "REJECTED_REPORT", "CLIENT_CONNECT"}
    check("T14 Central logger has controller + server events",
          {"controller", "app-server"} <= {e.get("source") for e in events} and need <= kinds,
          "%d events, missing=%s" % (len(events), sorted(need - kinds)))


def main():
    setLogLevel("warning")
    require_services()
    with open(LOG, "w", encoding="utf-8"):
        pass
    os.chmod(LOG, 0o666)
    ctl("MODE", mode="dynamic")
    net = None
    try:
        net = create_network()
        ctl("RESET")
        time.sleep(1)
        run(net)
    except Exception as exc:  # report instead of leaving Mininet running
        check("setup / execution", False, repr(exc))
    finally:
        if net is not None:
            stop_servers(net)
            net.stop()

    passed = sum(p for _, p, _ in results)
    lines = ["[%s] %s %s" % ("PASS" if p else "FAIL", n, d) for n, p, d in results]
    lines += ["", "%d/%d tests passed" % (passed, len(results)), "", "Measured timings:"]
    lines += ["  %-40s %s" % t for t in timings]
    text = "\n".join(lines) + "\n"
    with open(os.path.join(RESULTS, "test_results.txt"), "w") as f:
        f.write(text)
    print("\n" + text)
    print(json.dumps({"passed": passed, "total": len(results)}))
    raise SystemExit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
