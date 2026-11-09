"""Shared helpers for run_tests.py and benchmark.py (run as root, in the root namespace)."""
import json
import os
import socket
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "topology"))
sys.path.insert(0, os.path.join(ROOT, "app"))
from common import CONTROL_PORT, request  # noqa: E402
from topo import create_network  # noqa: E402,F401

APP = os.path.join(ROOT, "app")
LOG = os.path.join(ROOT, "logs", "security_events.log")
RESULTS = os.path.join(ROOT, "results")
SERVER = "10.0.0.2"
with open(os.path.join(ROOT, "controller", "policy.json")) as _f:
    DETECTION = json.load(_f)["detection"]


def require_services():
    for port, what in ((5514, "./run.sh logger"), (6653, "./run.sh controller")):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
        except OSError:
            sys.exit("Start '%s' first (port %d not reachable)." % (what, port))
    os.makedirs(RESULTS, exist_ok=True)


def ctl(cmd, **kw):
    return request("127.0.0.1", CONTROL_PORT, dict(cmd=cmd, **kw))


def start_servers(h2, ports=(5000, 8080, 23)):
    for port in ports:
        h2.cmd("python3 %s/tcp_server.py --port %d > %s/logs/server_%d.out 2>&1 &"
               % (APP, port, ROOT, port))
    time.sleep(1.5)


def stop_servers(net):
    net.get("h2").cmd("pkill -f tcp_server.py || true")


def client(host, args):
    return host.cmd("python3 %s/tcp_client.py %s" % (APP, args)).strip()


def tagged(output, tag):
    """Return the JSON object printed after `tag ` in a command's output."""
    for line in output.splitlines():
        if line.startswith(tag + " "):
            return json.loads(line[len(tag) + 1:])
    raise ValueError("no %s line in output: %r" % (tag, output[-300:]))


def attack_cmd(args):
    return "python3 %s/attacker.py %s" % (APP, args)


def probe_cmd(seconds, interval=0.2):
    return "python3 %s/tcp_client.py %s 5000 --probe %s --interval %s" % (
        APP, SERVER, seconds, interval)


def block_for(src, since, reason=None):
    """First block record for src created after `since` (epoch), or None."""
    for rec in ctl("STATUS").get("history", []):
        if rec["src"] == src and rec["blocked_at"] >= since and reason in (None, rec["reason"]):
            return rec
    return None


def wait(predicate, seconds, step=0.2):
    until = time.time() + seconds
    while time.time() < until:
        value = predicate()
        if value:
            return value
        time.sleep(step)
    return None


def log_events():
    found = []
    if os.path.exists(LOG):
        with open(LOG, encoding="utf-8") as f:
            for line in f:
                try:
                    found.append(json.loads(line))
                except ValueError:
                    pass
    return found
