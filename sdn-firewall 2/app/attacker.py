#!/usr/bin/env python3
"""Attack traffic generator for the robustness experiments (Mininet lab only).

  attacker.py flood HOST PORT --seconds 8 [--workers 8] [--rate 0] [--payload 1024]
      Connection flood: many short TCP sessions against an *allowed* service.
      --rate limits total new connections per second (0 = as fast as possible).
  attacker.py scan HOST --ports 4980-5020 [--workers 4] [--seconds 8]
      TCP connect scan.  A port is "open" (accepted), "closed" (RST) or
      "filtered" (no answer - dropped by the firewall).

Prints one line:  ATTACK {json summary}  (all times are epoch seconds).
"""
import argparse
import errno
import json
import socket
import threading
import time


class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.ok = self.fail = 0
        self.last_ok = self.first_fail = None

    def record(self, success):
        t = time.time()
        with self.lock:
            if success:
                self.ok += 1
                self.last_ok = t
            else:
                self.fail += 1
                self.first_fail = self.first_fail or t


def flood(args, stats, end):
    gap = args.workers / args.rate if args.rate else 0.0
    payload = b"HELLO flood\nMSG " + b"x" * args.payload + b"\n"

    def worker():
        while time.time() < end:
            t0 = time.time()
            try:
                with socket.create_connection((args.host, args.port), timeout=1) as s:
                    s.settimeout(1)
                    s.sendall(payload)
                    reply = s.recv(64)
                stats.record(reply.startswith(b"OK"))
            except OSError:
                stats.record(False)
            if gap:
                time.sleep(max(0.0, gap - (time.time() - t0)))
    return worker


def scan(args, stats, end, result):
    lo, _, hi = args.ports.partition("-")
    ports = list(range(int(lo), int(hi or lo) + 1))
    lock = threading.Lock()

    def worker():
        while time.time() < end:
            with lock:
                if not ports:
                    return
                port = ports.pop(0)
            s = socket.socket()
            s.settimeout(args.timeout)
            code = s.connect_ex((args.host, port))
            s.close()
            state = ("open" if code == 0 else
                     "closed" if code == errno.ECONNREFUSED else "filtered")
            with lock:
                result[state].append(port)
            stats.record(state != "filtered")
    return worker


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["flood", "scan"])
    ap.add_argument("host")
    ap.add_argument("port", type=int, nargs="?", default=5000)
    ap.add_argument("--seconds", type=float, default=8)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--rate", type=float, default=0)
    ap.add_argument("--payload", type=int, default=1024)
    ap.add_argument("--ports", default="4980-5020")
    ap.add_argument("--timeout", type=float, default=0.5)
    args = ap.parse_args()

    stats, result = Stats(), {"open": [], "closed": [], "filtered": []}
    start = time.time()
    end = start + args.seconds
    target = flood(args, stats, end) if args.mode == "flood" else scan(args, stats, end, result)
    threads = [threading.Thread(target=target, daemon=True) for _ in range(args.workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(args.seconds + 5)

    summary = {"mode": args.mode, "start": start, "end": time.time(),
               "ok": stats.ok, "fail": stats.fail,
               "last_ok": stats.last_ok, "first_fail": stats.first_fail}
    if args.mode == "scan":
        summary.update(open=sorted(result["open"]), closed=len(result["closed"]),
                       filtered=len(result["filtered"]),
                       probed=sum(len(v) for v in result.values()))
    print("ATTACK " + json.dumps(summary), flush=True)


if __name__ == "__main__":
    main()
