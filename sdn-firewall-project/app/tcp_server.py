#!/usr/bin/env python3
"""Multi-client TCP application server (thread per client).

Protocol (line based):  HELLO <name> | MSG <text> | BYE
Anything else is a protocol violation.  After N violations from one client IP
the server reports the client to the SDN controller (control channel), which
installs a block rule.  Connection events are sent to the central logger.
"""
import argparse
import os
import socket
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (APP_PORT, CONTROL_PORT, LOGGER_PORT, MGMT_IP, now, send_json)

violations = {}
lock = threading.Lock()


def log_event(args, event, **kw):
    rec = {"ts": now(), "source": "app-server", "event": event, **kw}
    threading.Thread(target=send_json, args=(args.logger, LOGGER_PORT, rec), daemon=True).start()


def handle(conn, addr, args):
    ip = addr[0]
    name = "?"
    conn.settimeout(30)
    log_event(args, "CLIENT_CONNECT", src=ip, port=args.port)
    try:
        rf = conn.makefile("r", encoding="utf-8", newline="\n")
        for line in rf:
            line = line.strip()
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
            else:
                with lock:
                    violations[ip] = violations.get(ip, 0) + 1
                    n = violations[ip]
                conn.sendall(b"ERR unknown command\n")
                log_event(args, "BAD_COMMAND", src=ip, count=n, cmd=cmd[:20])
                if n >= args.violations:
                    with lock:
                        violations[ip] = 0
                    send_json(args.controller, CONTROL_PORT, {
                        "event": "APP_VIOLATION", "src": ip, "client": name,
                        "reason": "%d malformed commands" % n})
                    conn.sendall(b"ERR too many violations\n")
                    break
    except (OSError, UnicodeDecodeError):
        pass
    finally:
        conn.close()
        log_event(args, "CLIENT_DISCONNECT", src=ip, port=args.port)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=APP_PORT)
    ap.add_argument("--violations", type=int, default=3)
    ap.add_argument("--controller", default=MGMT_IP)
    ap.add_argument("--logger", default=MGMT_IP)
    args = ap.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(64)
    print("server listening on %s:%d" % (args.host, args.port), flush=True)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr, args), daemon=True).start()


if __name__ == "__main__":
    main()
