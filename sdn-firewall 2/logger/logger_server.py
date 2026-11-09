#!/usr/bin/env python3
"""Centralized security-event logger (TCP, thread per connection).

Receives JSON lines from the SDN controller and the app server, stamps them
and appends them to logs/security_events.log.
"""
import json
import os
import socket
import sys
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "app"))
from common import LOGGER_PORT, now

LOGFILE = os.path.join(ROOT, "logs", "security_events.log")
lock = threading.Lock()
MAX_PER_IP = 8          # concurrent connections per source address
MAX_TOTAL = 64
FIRST_LINE_TIMEOUT = 10  # a connection must send something quickly (no idle hoarding)
active = {}


def handle(conn, addr):
    try:
        conn.settimeout(FIRST_LINE_TIMEOUT)
        rf = conn.makefile("r", encoding="utf-8", newline="\n")
        for line in rf:
            line = line.strip()
            if not line:
                continue
            conn.settimeout(None)       # established senders may idle between events
            try:
                rec = json.loads(line)
            except ValueError:
                rec = None
            if not isinstance(rec, dict):
                rec = {"event": "RAW", "msg": line[:2000]}
            rec["logger_ts"] = now()
            rec["from"] = addr[0]
            out = json.dumps(rec)
            with lock:
                with open(LOGFILE, "a") as f:
                    f.write(out + "\n")
            print(out, flush=True)
    except OSError:
        pass
    finally:
        conn.close()
        with lock:
            active[addr[0]] = active.get(addr[0], 1) - 1


def main():
    os.makedirs(os.path.dirname(LOGFILE), exist_ok=True)
    open(LOGFILE, "a").close()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", LOGGER_PORT))
    srv.listen(64)
    print("logger listening on 0.0.0.0:%d -> %s" % (LOGGER_PORT, LOGFILE), flush=True)
    while True:
        conn, addr = srv.accept()
        with lock:
            if active.get(addr[0], 0) >= MAX_PER_IP or sum(active.values()) >= MAX_TOTAL:
                conn.close()
                continue
            active[addr[0]] = active.get(addr[0], 0) + 1
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
