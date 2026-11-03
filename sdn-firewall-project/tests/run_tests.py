#!/usr/bin/env python3
"""D1-only Mininet smoke test. Start logger and Ryu first.

Writes test results to results/d1_test_results.txt.
"""
import json
import os
import socket
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "topology"))
from topo import create_network
from mininet.log import setLogLevel

APP = os.path.join(ROOT, "app")
LOG = os.path.join(ROOT, "logs", "security_events.log")
OUTPUT = os.path.join(ROOT, "results", "d1_test_results.txt")
SERVER = "10.0.0.2"
results = []


def ready(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return True
    except OSError:
        return False


def client(host, opts):
    return host.cmd("python3 %s/tcp_client.py %s" % (APP, opts))


def events():
    if not os.path.exists(LOG):
        return []
    found = []
    with open(LOG, encoding="utf-8") as f:
        for line in f:
            try:
                found.append(json.loads(line))
            except ValueError:
                continue
    return found


def has_event(event, src=None):
    return any(x.get("event") == event and
               (src is None or x.get("src") == src) for x in events())


def wait_for(event, src=None, seconds=5):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        if has_event(event, src):
            return True
        time.sleep(0.2)
    return False


def check(label, passed, detail=""):
    results.append((label, bool(passed), detail))
    print("[%s] %s %s" % ("PASS" if passed else "FAIL", label, detail), flush=True)


def main():
    setLogLevel("warning")
    os.makedirs(os.path.join(ROOT, "results"), exist_ok=True)
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    if not (ready(5514) and ready(6653)):
        sys.exit("Start './run.sh logger' and './run.sh controller' first.")
    with open(LOG, "w", encoding="utf-8"):
        pass
    os.chmod(LOG, 0o666)

    net = None
    try:
        net = create_network()
        h1, h2, h3, h4 = (net.get("h%d" % n) for n in range(1, 5))
        time.sleep(3)
        net.pingAll(timeout=2)  # ARP / MAC learning warm-up
        loss = net.pingAll(timeout=2)
        check("D1-1 Mininet host connectivity", loss == 0, "loss=%s%%" % loss)

        h2.cmd("python3 %s/tcp_server.py --port 5000 > %s/logs/server_5000.out 2>&1 &" %
               (APP, ROOT))
        # Listen on a denied port as proof the firewall, not missing service,
        # prevents the connection.
        h2.cmd("python3 %s/tcp_server.py --port 23 > %s/logs/server_23.out 2>&1 &" %
               (APP, ROOT))
        time.sleep(1.5)

        good = client(h1, "%s 5000 --name h1 --msgs 3" % SERVER)
        check("D1-2 Allowed TCP app exchange", "RESULT OK" in good, good.strip())

        h1.sendCmd("python3 %s/tcp_client.py %s 5000 --name h1 --msgs 10" %
                   (APP, SERVER))
        h3.sendCmd("python3 %s/tcp_client.py %s 5000 --name h3 --msgs 10" %
                   (APP, SERVER))
        o1, o3 = h1.waitOutput(), h3.waitOutput()
        check("D1-3 Concurrent TCP clients",
              "RESULT OK" in o1 and "RESULT OK" in o3)

        denied = client(h4, "%s 23 --name h4 --timeout 2" % SERVER)
        check("D1-4 Port 23 denied by SDN firewall",
              "RESULT FAIL" in denied and wait_for("DENY", "10.0.0.4"),
              denied.strip())

        malformed = client(h3, "%s 5000 --name h3 --bad 3" % SERVER)
        reported = wait_for("APP_VIOLATION", "10.0.0.3")
        blocked = wait_for("BLOCK", "10.0.0.3")
        flows = net.get("s1").cmd("ovs-ofctl -O OpenFlow13 dump-flows s1")
        check("D1-5 Socket event triggers SDN block",
              "RESULT OK" in malformed and reported and blocked and
              "priority=200" in flows,
              "violation=%s block=%s rule=%s" %
              (reported, blocked, "priority=200" in flows))

        log_sources = {e.get("source") for e in events()}
        check("D1-6 Central logger receives events",
              {"controller", "app-server"} <= log_sources,
              "sources=%s" % sorted(log_sources))
    except Exception as exc:
        check("D1 setup / execution", False, str(exc))
    finally:
        if net is not None:
            try:
                net.get("h2").cmd("pkill -f tcp_server.py || true")
            finally:
                net.stop()

    passed = sum(ok for _, ok, _ in results)
    summary = "\n".join("[%s] %s %s" %
                        ("PASS" if ok else "FAIL", name, detail)
                        for name, ok, detail in results)
    summary += "\n\n%d/%d D1 tests passed\n" % (passed, len(results))
    with open(OUTPUT, "w", encoding="utf-8") as out:
        out.write(summary)
    print("\n" + summary)
    raise SystemExit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
