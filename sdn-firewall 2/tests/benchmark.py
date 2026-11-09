#!/usr/bin/env python3
"""Performance evaluation: dynamic firewall vs static (allow/deny only) baseline.

For every (mode, scenario) a legitimate client h1 runs a 12 s latency probe
(one session every 0.2 s) while attacker h4 attacks for 8 s starting at t=2 s.
Links are shaped to 10 Mbit/s so congestion is visible.

Metrics: legit success %, avg / p95 session latency, attack sessions served
(or services discovered by the scan), blocking response time (attack start ->
block rule installed) and time until attack traffic stopped getting through.

    sudo python3 tests/benchmark.py [--repeat N]
      -> results/benchmark.md, results/benchmark.csv
"""
import argparse
import csv
import os
import time

from mininet.log import setLogLevel

from lab import (RESULTS, SERVER, attack_cmd, block_for, create_network, ctl,
                 probe_cmd, require_services, start_servers, stop_servers, tagged)

PROBE_S, ATTACK_DELAY_S, ATTACK_S = 12, 2, 8
SCENARIOS = {
    "no attack": None,
    "flood 50 conn/s": "flood %s 5000 --workers 4 --rate 50 --seconds %d" % (SERVER, ATTACK_S),
    "flood max rate": "flood %s 5000 --workers 16 --seconds %d" % (SERVER, ATTACK_S),
    "port scan": "scan %s --ports 4980-5020 --workers 4 --seconds %d" % (SERVER, ATTACK_S),
}
FIELDS = ["mode", "scenario", "run", "legit_success_pct", "legit_avg_ms", "legit_p95_ms",
          "legit_requests", "attack_served", "block_response_ms", "attack_stopped_after_ms"]


def ms(value):
    return round(value * 1000, 1) if value is not None else None


def one_run(net, mode, scenario, attack, run):
    h1, h4 = net.get("h1"), net.get("h4")
    ctl("MODE", mode=mode)
    ctl("RESET")
    time.sleep(1.5)
    h1.sendCmd(probe_cmd(PROBE_S))
    summary = None
    if attack:
        time.sleep(ATTACK_DELAY_S)
        h4.sendCmd(attack_cmd(attack))
        summary = tagged(h4.waitOutput(), "ATTACK")
    probe = tagged(h1.waitOutput(), "PROBE")
    row = {"mode": mode, "scenario": scenario, "run": run,
           "legit_success_pct": probe["success_pct"], "legit_avg_ms": probe["avg_ms"],
           "legit_p95_ms": probe["p95_ms"], "legit_requests": probe["requests"],
           "attack_served": "-", "block_response_ms": "-", "attack_stopped_after_ms": "-"}
    if summary:
        rec = block_for("10.0.0.4", summary["start"])
        row["attack_served"] = (summary["ok"] if summary["mode"] == "flood"
                                else "open ports %s" % summary["open"])
        row["block_response_ms"] = ms(rec["blocked_at"] - summary["start"]) if rec else "never"
        stopped = summary["last_ok"]
        row["attack_stopped_after_ms"] = (ms(stopped - summary["start"]) if rec and stopped
                                          else "none got through" if rec else "never")
    print("  %-8s %-16s run %d -> %s" % (mode, scenario, run, row), flush=True)
    return row


def write(rows):
    with open(os.path.join(RESULTS, "benchmark.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    head = ["Mode", "Scenario", "Run", "Legit OK %", "Avg ms", "p95 ms", "Requests",
            "Attack served", "Block response ms", "Attack stopped after ms"]
    lines = ["# Benchmark: dynamic firewall vs static baseline", "",
             "Probe %ds on h1 (1 session / 0.2 s); attack %ds from h4 starting at t=%ds; "
             "10 Mbit/s links." % (PROBE_S, ATTACK_S, ATTACK_DELAY_S), "",
             "| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    lines += ["| " + " | ".join(str(r[k]) for k in FIELDS) + " |" for r in rows]
    text = "\n".join(lines) + "\n"
    with open(os.path.join(RESULTS, "benchmark.md"), "w") as f:
        f.write(text)
    print("\n" + text)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repeat", type=int, default=1, help="runs per (mode, scenario)")
    args = ap.parse_args()
    setLogLevel("warning")
    require_services()
    rows, net = [], None
    try:
        net = create_network(bw=10)
        net.pingAll(timeout=1)
        start_servers(net.get("h2"), (5000,))
        for scenario, attack in SCENARIOS.items():
            for mode in ("static", "dynamic"):
                for run in range(1, args.repeat + 1):
                    rows.append(one_run(net, mode, scenario, attack, run))
    finally:
        ctl("MODE", mode="dynamic")
        ctl("RESET")
        if net is not None:
            stop_servers(net)
            net.stop()
    write(rows)


if __name__ == "__main__":
    main()
