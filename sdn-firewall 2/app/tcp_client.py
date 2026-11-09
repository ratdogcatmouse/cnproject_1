#!/usr/bin/env python3
"""TCP client: normal sessions, malformed-command sessions, and latency probing.

  tcp_client.py HOST PORT [--msgs N] [--delay S]   normal session
  tcp_client.py HOST PORT --bad N                  send N malformed commands
  tcp_client.py HOST PORT --probe SECONDS          repeat 1-message sessions and
                                                   print latency stats as JSON
"""
import argparse
import json
import socket
import time


def session(host, port, name, count, bad, timeout, delay=0.0):
    """Run one protocol session; raise OSError/ConnectionError on failure."""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        stream = sock.makefile("r", encoding="utf-8")

        def send(message):
            sock.sendall((message + "\n").encode())
            answer = stream.readline()
            if not answer:
                raise ConnectionError("connection closed")
            return answer.strip()

        reply = send("HELLO " + name)
        if not reply.startswith("OK"):
            raise ConnectionError("HELLO rejected: " + reply)
        if bad:
            for n in range(bad):
                send("BOGUS%d" % n)
            return
        for n in range(count):
            reply = send("MSG hello-%d" % n)
            if reply != "ECHO hello-%d" % n:
                raise ConnectionError("unexpected response: " + reply)
            if delay:
                time.sleep(delay)
        send("BYE")


def probe(host, port, seconds, interval, timeout):
    """Legitimate-user probe: one short session every `interval` seconds."""
    latencies, failures = [], 0
    start = time.time()
    while time.time() - start < seconds:
        t0 = time.time()
        try:
            session(host, port, "probe", 1, 0, timeout)
            latencies.append((time.time() - t0) * 1000)
        except (OSError, ConnectionError):
            failures += 1
        time.sleep(max(0.0, interval - (time.time() - t0)))
    latencies.sort()
    n = len(latencies)
    stats = {"requests": n + failures, "ok": n, "fail": failures,
             "success_pct": round(100.0 * n / max(1, n + failures), 1),
             "avg_ms": round(sum(latencies) / n, 2) if n else None,
             "p95_ms": round(latencies[int(0.95 * (n - 1))], 2) if n else None,
             "max_ms": round(latencies[-1], 2) if n else None}
    print("PROBE " + json.dumps(stats), flush=True)
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("--name", default="client")
    parser.add_argument("--msgs", type=int, default=3)
    parser.add_argument("--delay", type=float, default=0.0)
    parser.add_argument("--bad", type=int, default=0)
    parser.add_argument("--timeout", type=float, default=2)
    parser.add_argument("--probe", type=float, default=0, metavar="SECONDS")
    parser.add_argument("--interval", type=float, default=0.2)
    args = parser.parse_args()
    if args.probe:
        raise SystemExit(probe(args.host, args.port, args.probe, args.interval, args.timeout))
    try:
        session(args.host, args.port, args.name, args.msgs, args.bad, args.timeout, args.delay)
        print("RESULT OK " + ("malformed commands sent=%d" % args.bad if args.bad
                              else "messages=%d" % args.msgs))
        raise SystemExit(0)
    except (OSError, ConnectionError) as error:
        print("RESULT FAIL %s" % error)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
