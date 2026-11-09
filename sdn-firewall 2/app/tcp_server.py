#!/usr/bin/env python3
"""Multi-client TCP application server (thread per client).

Protocol (line based):  HELLO <name> | MSG <text> | BYE
Anything else (or a line longer than MAX_LINE) is a protocol violation.  After
N violations from one client IP the server reports the client to the SDN
controller over TCP; the controller installs a block rule.  Connection events
are streamed to the central security logger.  At most --max-clients sessions
are served at once; extra connections get "ERR busy" (overload protection).
"""
import argparse
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (APP_PORT, CONTROL_PORT, LOGGER_PORT, MGMT_IP, EventSender,
                    now, send_json)

MAX_LINE = 4096
violations = {}
lock = threading.Lock()


def log_event(args, event, **kw):
    args.events.send({"ts": now(), "epoch": round(time.time(), 6),
                      "source": "app-server", "event": event, "port": args.port, **kw})


def violation(conn, args, ip, name, what):
    """Count a protocol violation; return True when the client was reported."""
    with lock:
        violations[ip] = violations.get(ip, 0) + 1
        n = violations[ip]
        if n >= args.violations:
            violations[ip] = 0
    conn.sendall(b"ERR unknown command\n")
    log_event(args, "BAD_COMMAND", src=ip, count=n, cmd=what[:20])
    if n < args.violations:
        return False
    send_json(args.controller, CONTROL_PORT, {
        "event": "APP_VIOLATION", "src": ip, "client": name,
        "reason": "%d malformed commands" % n, "epoch": time.time()})
    conn.sendall(b"ERR too many violations\n")
    return True


def handle(conn, addr, args):
    ip = addr[0]
    name = "?"
    conn.settimeout(30)
    log_event(args, "CLIENT_CONNECT", src=ip)
    try:
        rf = conn.makefile("r", encoding="utf-8", newline="\n")
        while True:
            raw = rf.readline(MAX_LINE)
            if not raw:
                break
            if len(raw) >= MAX_LINE and not raw.endswith("\n"):
                if violation(conn, args, ip, name, "LINE_TOO_LONG"):
                    break
                rf.readline()           # discard the rest of the oversized line
                continue
            line = raw.strip()
            if not line:
                continue
            cmd, _, rest = line.partition(" ")
            cmd = cmd.upper()
            if cmd == "HELLO":
                name = rest or "anon"
                conn.sendall(("OK welcome %s\n" % name).encode())
            elif cmd == "MSG":
                conn.sendall(("ECHO %s\n" % rest).encode())
            elif cmd == "BYE":
                conn.sendall(b"OK bye\n")
                break
            elif violation(conn, args, ip, name, cmd):
                break
    except (OSError, UnicodeDecodeError):
        pass
    finally:
        conn.close()
        args.slots.release()
        log_event(args, "CLIENT_DISCONNECT", src=ip)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=APP_PORT)
    ap.add_argument("--violations", type=int, default=3)
    ap.add_argument("--max-clients", type=int, default=100)
    ap.add_argument("--controller", default=MGMT_IP)
    ap.add_argument("--logger", default=MGMT_IP)
    args = ap.parse_args()
    args.events = EventSender(args.logger, LOGGER_PORT)
    args.slots = threading.BoundedSemaphore(args.max_clients)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(128)
    print("server listening on %s:%d" % (args.host, args.port), flush=True)
    while True:
        conn, addr = srv.accept()
        if not args.slots.acquire(blocking=False):
            try:
                conn.sendall(b"ERR busy\n")
            except OSError:
                pass
            conn.close()
            log_event(args, "SERVER_BUSY", src=addr[0])
            continue
        threading.Thread(target=handle, args=(conn, addr, args), daemon=True).start()


if __name__ == "__main__":
    main()
