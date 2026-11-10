#!/usr/bin/env python3
"""Live security dashboard for the SDN dynamic firewall.

This is an ADDITIVE component: it only reads logs/security_events.log and talks
to the controller's existing control channel (TCP 9999, localhost). It does not
modify or import any other project file, and needs nothing beyond Python 3.

  python3 dashboard/server.py            live mode  (logger + controller running)
  python3 dashboard/server.py --demo     narrated simulation, works without Mininet

Then open http://127.0.0.1:8000 in a browser.
"""
import argparse
import ipaddress
import json
import os
import random
import socket
import sys
import threading
import time
from collections import Counter, defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DEFAULT_LOG = os.path.join(ROOT, "logs", "security_events.log")
CONTROL_ADDR = ("127.0.0.1", 9999)      # controller control channel
LOGGER_ADDR = ("127.0.0.1", 5514)       # central logger
SERVER_IP = "10.0.0.2"
TIMELINE_SECONDS = 60
KIND = {"ALLOW": "allow", "DENY": "deny", "BLOCK": "block"}


# --------------------------------------------------------------------- event store
class Store:
    """In-memory view of the event stream: recent events, counters, per-second buckets."""

    def __init__(self):
        self.lock = threading.Lock()
        self.seq = 0            # never goes backwards, so browsers can ask "since N"
        self.generation = 0     # bumped on clear() so browsers know to drop their feed
        self._reset()

    def _reset(self):
        self.events = deque(maxlen=500)
        self.counts = Counter()
        self.hosts = defaultdict(Counter)
        self.buckets = defaultdict(Counter)

    def clear(self):
        with self.lock:
            self._reset()
            self.generation += 1

    def add(self, rec):
        ev = str(rec.get("event", "RAW"))
        try:
            epoch = float(rec.get("epoch"))
        except (TypeError, ValueError):
            epoch = time.time()
        with self.lock:
            self.seq += 1
            rec["seq"] = self.seq
            rec["event"] = ev
            self.counts[ev] += 1
            src = rec.get("src")
            if isinstance(src, str):
                self.hosts[src][ev] += 1
            kind = KIND.get(ev)
            if kind:
                self.buckets[int(epoch)][kind] += 1
            self.events.append(rec)
            if len(self.buckets) > 400:
                cutoff = int(time.time()) - 300
                for k in [k for k in self.buckets if k < cutoff]:
                    del self.buckets[k]

    def snapshot(self, since):
        now = int(time.time())
        with self.lock:
            events = [e for e in self.events if e["seq"] > since][-200:]
            timeline = []
            for sec in range(now - TIMELINE_SECONDS + 1, now + 1):
                b = self.buckets.get(sec, {})
                timeline.append([b.get("allow", 0), b.get("deny", 0), b.get("block", 0)])
            return {"seq": self.seq, "generation": self.generation, "events": events,
                    "counts": dict(self.counts),
                    "hosts": {ip: dict(c) for ip, c in self.hosts.items()},
                    "timeline": timeline}


# --------------------------------------------------------------------- live backend
def control_request(obj, timeout=2.0):
    """Send one JSON line to the controller control channel, return its JSON reply."""
    try:
        with socket.create_connection(CONTROL_ADDR, timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall((json.dumps(obj) + "\n").encode())
            line = s.makefile("r", encoding="utf-8").readline()
        return json.loads(line) if line else {"ok": False, "error": "no reply"}
    except (OSError, ValueError) as error:
        return {"ok": False, "error": str(error)}


def port_open(addr):
    try:
        socket.create_connection(addr, timeout=0.4).close()
        return True
    except OSError:
        return False


class LiveBackend:
    demo = False

    def __init__(self, store, log_path, fresh):
        self.store, self.log_path, self.fresh = store, log_path, fresh
        self.lock = threading.Lock()
        self._status = {"ok": False, "error": "not polled yet"}
        self._polled = time.time()
        self._logger_up = False

    def start(self):
        threading.Thread(target=self._tail, daemon=True).start()
        threading.Thread(target=self._poll, daemon=True).start()

    def _tail(self):
        """Follow the log file; copes with truncation (tests/run_tests.py truncates it)."""
        pos = 0
        if self.fresh:
            try:
                pos = os.path.getsize(self.log_path)
            except OSError:
                pos = 0
        while True:
            try:
                size = os.path.getsize(self.log_path)
            except OSError:
                time.sleep(0.5)
                continue
            if size < pos:                      # file was truncated -> start over
                self.store.clear()
                pos = 0
            if size > pos:
                with open(self.log_path, "rb") as f:
                    f.seek(pos)
                    data = f.read(size - pos)
                end = data.rfind(b"\n")         # only consume complete lines
                if end >= 0:
                    pos += end + 1
                    for line in data[:end + 1].splitlines():
                        try:
                            rec = json.loads(line.decode("utf-8", "replace"))
                        except ValueError:
                            continue
                        if isinstance(rec, dict):
                            self.store.add(rec)
            time.sleep(0.25)

    def _poll(self):
        n = 0
        while True:
            reply = control_request({"cmd": "STATUS"})
            with self.lock:
                self._status, self._polled = reply, time.time()
                if n % 3 == 0:
                    self._logger_up = port_open(LOGGER_ADDR)
            n += 1
            time.sleep(1)

    def status(self):
        with self.lock:
            return dict(self._status), self._polled

    def logger_up(self):
        with self.lock:
            return self._logger_up

    def command(self, req):
        return control_request(req)


# --------------------------------------------------------------------- demo backend
HOST = {"10.0.0.1": "h1", "10.0.0.2": "h2", "10.0.0.3": "h3", "10.0.0.4": "h4", "10.0.0.5": "h5"}
H1, H3, H4, H5 = "10.0.0.1", "10.0.0.3", "10.0.0.4", "10.0.0.5"


class DemoBackend:
    """A narrated, scripted walk-through of the firewall (no Mininet needed).

    It emits the same event shapes as the real controller, plus NARRATION events
    which the page shows as pop-ups: who is trying what, which rule applies, what
    is allowed and what is denied. It can be paused from the page, and --speed
    changes the pace. It also reacts to the mode switch (static mode = no defence)."""
    demo = True
    CLIENTS = (H1, H3, H4)

    def __init__(self, store, speed=1.0):
        self.store = store
        self.speed = max(0.25, min(float(speed), 8.0))
        self.lock = threading.RLock()
        self.mode = "dynamic"
        self.paused = False
        self.clock = 0.0                      # demo clock: stops while paused
        self.blocked, self.since = {}, {}
        self.offences, self.history = Counter(), []

    def start(self):
        threading.Thread(target=self._ticker, daemon=True).start()
        threading.Thread(target=self._script, daemon=True).start()

    def logger_up(self):
        return True

    # ---- plumbing
    def emit(self, event, source="controller", **kw):
        now = time.time()
        ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now)) + ".%03d" % (int(now * 1000) % 1000)
        self.store.add({"ts": ts, "epoch": round(now, 6), "source": source, "event": event, **kw})

    def wait(self, seconds):
        """Sleep (scaled by --speed); freezes while the demo is paused."""
        left = seconds / self.speed
        while left > 0:
            if self.paused:
                time.sleep(0.1)
                continue
            step = min(0.05, left)
            time.sleep(step)
            left -= step

    def is_blocked(self, ip):
        with self.lock:
            return ip in self.blocked

    def block(self, src, reason, detail):
        """Install a block like the controller does; returns the record, or None (static mode)."""
        with self.lock:
            if self.mode != "dynamic" or src in self.blocked:
                return None
            self.offences[src] += 1
            n = self.offences[src]
            seconds = min(10 * 2 ** (n - 1), 120)
            now = time.time()
            self.blocked[src], self.since[src] = self.clock + seconds, self.clock
            rec = {"src": src, "reason": reason, "detail": detail, "seconds": seconds,
                   "offence": n, "blocked_at": now, "first_seen": now - 0.3}
            self.history.append(rec)
        self.emit("BLOCK", **rec)
        return rec

    def _release(self, ip, reason):
        with self.lock:
            if ip not in self.blocked:
                return
            del self.blocked[ip]
            held = self.clock - self.since.pop(ip, self.clock)
        self.emit("UNBLOCK", src=ip, reason=reason, blocked_for=round(held, 3))

    def _ticker(self):
        last = time.monotonic()
        while True:
            time.sleep(0.1)
            now = time.monotonic()
            dt, last = now - last, now
            if self.paused:
                continue
            with self.lock:
                self.clock += dt
                due = [ip for ip, exp in self.blocked.items() if exp <= self.clock]
            for ip in due:
                self._release(ip, "timeout")

    # ---- story helpers
    def say(self, step, title, text, verdict="info", actors=(), rules=(), hold=8):
        """Pop-up on the page. verdict: allow | deny | block | recover | alert | info.
        rules: (kind, text) with kind allow | deny | note."""
        self.emit("NARRATION", source="demo", step=step, title=title, text=text, verdict=verdict,
                  actors=list(actors), rules=[{"kind": k, "text": t} for k, t in rules],
                  hold=round(hold / self.speed, 1))

    def allow(self, src, dport=5000, rule="app-service"):
        self.emit("ALLOW", src=src, dst=SERVER_IP, dport=dport, rule=rule)
        if dport == 5000:
            self.emit("CLIENT_CONNECT", source="app-server", src=src, port=dport)

    def deny(self, src, dport, rule="default"):
        self.emit("DENY", src=src, dst=SERVER_IP, dport=dport, rule=rule)

    def traffic(self, seconds, gap=1.2):
        """Quiet background traffic: one allowed flow every `gap` seconds."""
        for i in range(max(1, int(seconds / gap))):
            live = [ip for ip in self.CLIENTS if not self.is_blocked(ip)]
            if live:
                self.allow(live[i % len(live)])
            self.wait(gap)

    def traffic_until_released(self, ip, gap=1.2):
        i = 0
        while self.is_blocked(ip):
            live = [h for h in self.CLIENTS if not self.is_blocked(h)]
            if live:
                self.allow(live[i % len(live)])
            i += 1
            self.wait(gap)

    def _blocked_and_recovered(self, step, src, rec, what, rules):
        """Narrate the block, wait for the automatic recovery, narrate that too."""
        name = HOST[src]
        self.say(step, "%s is blocked for %d s" % (name, rec["seconds"]), what, "block", [src], rules, hold=10)
        self.traffic_until_released(src)
        self.say(step, "%s has recovered" % name,
                 "The block timer ran out, the switch removed the drop rule and told the controller. "
                 "%s follows the normal policy again - no administrator was needed." % name,
                 "recover", [src], [("allow", "ALLOW  %s → h2:5000   again" % name)], hold=8)
        self.allow(src)
        self.wait(1.5)
        self.traffic(5)

    def _not_blocked(self, step, what):
        self.say(step, "Static mode: nothing happens", what + " Switch the mode back to DYNAMIC (button at the "
                 "top) and the same attack gets blocked.", "alert", [],
                 [("note", "Static mode = fixed allow/deny rules only, no detection, no automatic blocking")], hold=10)
        self.traffic(8)

    # ---- the story
    def reset_story(self):
        with self.lock:
            self.blocked.clear()
            self.since.clear()
            self.offences.clear()
            self.history.clear()
        self.emit("RESET", mode=self.mode)

    def _script(self):
        first = True
        while True:
            if not first:
                self.reset_story()
            first = False
            self.intro()
            self.scene_normal()
            self.scene_untrusted()
            self.scene_telnet()
            self.scene_admin()
            self.scene_app_violation()
            self.scene_port_scan()
            self.scene_flood()
            self.scene_forged()
            self.say("Done", "Scenario complete",
                     "That was the full cycle: allow rules, deny rules, automatic detection, blocking, "
                     "recovery and a protected control channel. The scenario restarts in a few seconds.",
                     "info", [], [], hold=7)
            self.wait(9)

    def intro(self):
        self.say("Intro", "Five hosts, one application server",
                 "h2 (10.0.0.2) runs the TCP application. The controller enforces the rules below and also "
                 "watches for abuse - bad commands, port scans and connection floods lead to an automatic, "
                 "temporary block. Watch what each host tries and what the firewall decides.",
                 "info", [], [
                     ("allow", "ALLOW  any host → h2:5000   (rule app-service)"),
                     ("allow", "ALLOW  h1 → h2:8080, the admin port   (rule admin-service-h1-only)"),
                     ("deny", "DENY  h5, the untrusted host   (rule untrusted-host)"),
                     ("deny", "DENY  everything else   (default policy)")], hold=12)
        self.traffic(12)

    def scene_normal(self):
        self.say("Scene 1 of 8", "h1, h3 and h4 use the application",
                 "Each host opens a TCP connection to the app server on port 5000. A rule allows it, so the "
                 "controller lets the traffic through and the server answers.",
                 "allow", [H1, H3, H4], [("allow", "ALLOW  h1, h3, h4 → h2:5000   (rule app-service)")], hold=9)
        self.traffic(10)

    def scene_untrusted(self):
        self.say("Scene 2 of 8", "h5 tries to reach the application",
                 "h5 uses the same port 5000 that was just allowed for everyone else. But the untrusted-host "
                 "rule is checked first and denies everything that comes from 10.0.0.5, so the connection "
                 "never reaches the server.",
                 "deny", [H5], [("deny", "DENY  h5 → h2:5000   (rule untrusted-host, checked before app-service)")], hold=10)
        for _ in range(3):
            self.deny(H5, 5000, "untrusted-host")
            self.wait(2.6)
        self.traffic(2)

    def scene_telnet(self):
        self.say("Scene 3 of 8", "h4 tries port 23 (telnet)",
                 "A decoy service really is listening on port 23, but no rule allows it, so the default "
                 "policy (deny) applies. The firewall decides by rule, not by what happens to be running.",
                 "deny", [H4], [("deny", "DENY  h4 → h2:23   (default policy: deny)")], hold=9)
        for _ in range(3):
            self.deny(H4, 23)
            self.wait(2.4)
        self.traffic(2)

    def scene_admin(self):
        self.say("Scene 4 of 8", "Admin port 8080: h1 may, h3 may not",
                 "The admin service is open to one source host only. This is a source-based rule: same "
                 "destination, same port, different answer depending on who asks.",
                 "info", [H1, H3], [("allow", "ALLOW  h1 → h2:8080   (rule admin-service-h1-only)"),
                                    ("deny", "DENY  h3 → h2:8080   (default policy: deny)")], hold=10)
        self.wait(2)
        self.allow(H1, 8080, "admin-service-h1-only")
        self.wait(3)
        self.deny(H3, 8080)
        self.wait(4)
        self.traffic(2)

    def scene_app_violation(self):
        step = "Scene 5 of 8"
        self.say(step, "h3 sends malformed commands",
                 "h3 is allowed to connect, but what it sends is invalid. The app server counts bad commands "
                 "per client and, after 3, reports the host to the controller.",
                 "alert", [H3], [("note", "3 malformed commands → app server reports APP_VIOLATION to the controller"),
                                 ("note", "Controller in dynamic mode → installs a temporary BLOCK on the switch")], hold=11)
        self.wait(2)
        for i in range(1, 4):
            self.emit("BAD_COMMAND", source="app-server", src=H3, count=i, cmd="DROP TABLE")
            self.wait(1.6)
        self.emit("APP_VIOLATION", src=H3, reason="3 malformed commands", mode=self.mode)
        rec = self.block(H3, "APP_VIOLATION", "3 malformed commands")
        self.wait(1)
        if rec:
            self._blocked_and_recovered(step, H3, rec,
                "The controller installed a drop rule on the switch: every packet from h3 is discarded. "
                "h1 and h4 keep working normally, and the block removes itself when its timer ends.",
                [("deny", "DROP  everything from h3   (%d s, automatic)" % rec["seconds"]),
                 ("allow", "ALLOW  h1, h4 → h2:5000   unaffected")])
        else:
            self._not_blocked(step, "h3 keeps sending bad commands and nothing stops it.")

    def scene_port_scan(self):
        step = "Scene 6 of 8"
        self.say(step, "h4 scans for open ports",
                 "h4 probes port after port on h2, hoping to find a service to attack. Every probe is denied, "
                 "but the controller counts how many different ports one host has tried.",
                 "alert", [H4], [("deny", "DENY  each probe   (default policy: deny)"),
                                 ("note", "5 different denied ports within 5 s → PORT_SCAN → BLOCK")], hold=10)
        self.wait(2)
        rec, found = None, False
        for i, port in enumerate(range(4990, 5004)):
            if self.is_blocked(H4):
                break
            if port == 5000:
                self.allow(H4, 5000)
                found = True
                break
            self.deny(H4, port)
            if i == 5:
                rec = self.block(H4, "PORT_SCAN", "6 denied ports in 2.5s")
            self.wait(0.5)
        if rec:
            self._blocked_and_recovered(step, H4, rec,
                "The scan was caught after 6 probes, before it reached port 5000 where the real service "
                "lives. The attacker learned nothing and is cut off for a while.",
                [("deny", "DROP  everything from h4   (%d s, automatic)" % rec["seconds"])])
        elif found:
            self._not_blocked(step, "The scan reached port 5000 and found the application.")

    def scene_flood(self):
        step = "Scene 7 of 8"
        self.say(step, "h4 floods the server with connections",
                 "Opening connections as fast as possible can exhaust the server. The controller counts new "
                 "connections per host: 40 within 2 seconds counts as a flood. This is h4's second offence.",
                 "alert", [H4], [("note", "40 new connections within 2 s → CONN_FLOOD → BLOCK"),
                                 ("note", "Repeat offender → block time doubles (10 s, 20 s ... maximum 120 s)")], hold=11)
        self.wait(3)
        rec = None
        for i in range(70):
            if self.is_blocked(H4):
                break
            self.allow(H4)
            if i == 40:
                rec = self.block(H4, "CONN_FLOOD", "41 new connections in 1.9s")
            self.wait(0.045)
        if rec:
            self._blocked_and_recovered(step, H4, rec,
                "41 connections in under 2 seconds trips the flood detector. Because h4 already offended once, "
                "the block is twice as long as before.",
                [("deny", "DROP  everything from h4   (%d s, second offence)" % rec["seconds"])])
        else:
            self._not_blocked(step, "The flood continues and the server keeps answering the attacker.")

    def scene_forged(self):
        self.say("Scene 8 of 8", "h1 tries to fool the controller",
                 "A malicious host sends a fake violation report about h3 and an admin command to turn the "
                 "firewall off. Only the app server may report violations, and only localhost may send admin "
                 "commands, so both are rejected and logged.",
                 "deny", [H1], [("deny", "FORGED APP_VIOLATION about h3 → REJECTED (only the app server may report)"),
                                ("deny", "MODE command from h1 → REJECTED (admin commands only from localhost)"),
                                ("allow", "h3 is not blocked and the firewall stays in dynamic mode")], hold=12)
        self.wait(3)
        self.emit("REJECTED_REPORT", peer=H1, claimed_src=H3)
        self.wait(3)
        self.emit("REJECTED_COMMAND", peer=H1, cmd="MODE")
        self.wait(5)
        self.traffic(3)

    # ---- same interface as LiveBackend
    def status(self):
        with self.lock:
            return ({"ok": True, "mode": self.mode, "paused": self.paused,
                     "blocked": {ip: round(exp - self.clock, 1) for ip, exp in self.blocked.items()},
                     "offences": dict(self.offences), "history": list(self.history)}, time.time())

    def command(self, req):
        cmd = req.get("cmd")
        if cmd == "MODE":
            self.mode = req["mode"]
            self.emit("MODE_CHANGE", mode=self.mode)
        elif cmd == "UNBLOCK":
            self._release(req["src"], "removed")
        elif cmd == "RESET":
            self.reset_story()
        elif cmd == "DEMO":
            self.paused = req.get("action") == "pause"
        return {"ok": True}


# --------------------------------------------------------------------- HTTP layer
def build_state(backend, store, since):
    snap = store.snapshot(since)
    reply, polled = backend.status()
    now = time.time()
    ctl = {"up": bool(reply.get("ok")), "error": reply.get("error"), "mode": reply.get("mode")}
    blocked, history = [], []
    if reply.get("ok"):
        history = (reply.get("history") or [])[-15:]
        latest = {}
        for rec in reply.get("history") or []:
            latest[rec.get("src")] = rec
        for ip, remaining in (reply.get("blocked") or {}).items():
            rec = latest.get(ip, {})
            blocked.append({"src": ip,
                            "remaining": round(max(0.0, float(remaining) - (now - polled)), 1),
                            "total": rec.get("seconds"), "reason": rec.get("reason"),
                            "detail": rec.get("detail"), "offence": rec.get("offence")})
        ctl["offences"] = reply.get("offences") or {}
    snap.update({"now": now, "demo": backend.demo, "paused": bool(reply.get("paused")), "controller": ctl,
                 "logger_up": backend.logger_up(), "blocked": blocked, "history": history})
    return snap


def make_handler(backend, store):
    class Handler(BaseHTTPRequestHandler):
        server_version = "FirewallDashboard/1.0"

        def log_message(self, *args):       # keep the terminal quiet
            pass

        def _send(self, code, body, ctype="application/json"):
            if not isinstance(body, bytes):
                body = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            url = urlparse(self.path)
            if url.path in ("/", "/index.html"):
                with open(os.path.join(HERE, "index.html"), "rb") as f:
                    self._send(200, f.read(), "text/html; charset=utf-8")
            elif url.path == "/api/state":
                try:
                    since = int(parse_qs(url.query).get("since", ["0"])[0])
                except ValueError:
                    since = 0
                self._send(200, build_state(backend, store, since))
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self):
            # custom header: a web page on another origin cannot send it without a preflight
            if self.headers.get("X-Dashboard") != "1":
                return self._send(403, {"ok": False, "error": "forbidden"})
            try:
                length = int(self.headers.get("Content-Length") or 0)
                if length > 2048:
                    return self._send(413, {"ok": False, "error": "too large"})
                obj = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                return self._send(400, {"ok": False, "error": "bad json"})
            path = urlparse(self.path).path
            if path == "/api/clear":
                store.clear()
                return self._send(200, {"ok": True})
            if path != "/api/cmd" or not isinstance(obj, dict):
                return self._send(404, {"ok": False, "error": "not found"})
            cmd = str(obj.get("cmd", "")).upper()
            if cmd == "MODE" and obj.get("mode") in ("static", "dynamic"):
                req = {"cmd": "MODE", "mode": obj["mode"]}
            elif cmd == "UNBLOCK":
                try:
                    req = {"cmd": "UNBLOCK", "src": str(ipaddress.IPv4Address(obj.get("src")))}
                except ValueError:
                    return self._send(400, {"ok": False, "error": "bad ip"})
            elif cmd == "RESET":
                req = {"cmd": "RESET"}
            elif cmd == "DEMO" and backend.demo and obj.get("action") in ("pause", "resume"):
                req = {"cmd": "DEMO", "action": obj["action"]}
            else:
                return self._send(400, {"ok": False, "error": "unsupported command"})
            self._send(200, backend.command(req))

    return Handler


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1", help="bind address (default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--log", default=DEFAULT_LOG, help="security event log to follow")
    ap.add_argument("--demo", action="store_true", help="simulated traffic, no Mininet needed")
    ap.add_argument("--speed", type=float, default=1.0,
                    help="demo pace: 1 = narrated and slow (default), 2 = twice as fast")
    ap.add_argument("--fresh", action="store_true",
                    help="ignore events already in the log; show only new ones")
    args = ap.parse_args()

    store = Store()
    backend = DemoBackend(store, args.speed) if args.demo else LiveBackend(store, args.log, args.fresh)
    backend.start()
    try:
        httpd = ThreadingHTTPServer((args.host, args.port), make_handler(backend, store))
    except OSError as error:
        sys.exit("cannot listen on %s:%d (%s) - try --port 8001" % (args.host, args.port, error))
    httpd.daemon_threads = True
    mode = "DEMO (simulated traffic)" if args.demo else "LIVE (following %s)" % args.log
    print("Firewall dashboard: http://%s:%d   [%s]" % (args.host, args.port, mode), flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
