"""Shared helpers for the TCP application components."""
import json
import queue
import socket
import threading
import time

MGMT_IP = "10.0.0.100"     # management interface (controller + logger live here)
LOGGER_PORT = 5514         # centralized security-event logger (TCP)
CONTROL_PORT = 9999        # controller control channel (TCP)
APP_PORT = 5000            # application server port


def now():
    t = time.time()
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(t)) + ".%03d" % (int(t * 1000) % 1000)


def send_json(host, port, obj, timeout=1.5):
    """Send one JSON line over a short-lived TCP connection."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall((json.dumps(obj) + "\n").encode())
        return True
    except OSError:
        return False


def request(host, port, obj, timeout=3):
    """Send one JSON line and return the JSON reply line (or an error dict)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall((json.dumps(obj) + "\n").encode())
            line = s.makefile("r", encoding="utf-8").readline()
        return json.loads(line) if line else {"ok": False, "error": "no reply"}
    except (OSError, ValueError) as error:
        return {"ok": False, "error": str(error)}


class EventSender:
    """Streams JSON events to the logger over one persistent TCP connection.

    A background thread drains a queue, so callers never block and a busy
    server does not open a new logger connection (and a new SDN flow) per event.
    """

    def __init__(self, host, port):
        self.addr = (host, port)
        self.q = queue.Queue(maxsize=10000)
        threading.Thread(target=self._run, daemon=True).start()

    def send(self, obj):
        try:
            self.q.put_nowait(obj)
        except queue.Full:
            pass

    def _run(self):
        conn = None
        while True:
            line = (json.dumps(self.q.get()) + "\n").encode()
            for _ in range(2):          # one reconnect attempt per event
                try:
                    if conn is None:
                        conn = socket.create_connection(self.addr, timeout=1.5)
                    conn.sendall(line)
                    break
                except OSError:
                    if conn is not None:
                        conn.close()
                    conn = None
