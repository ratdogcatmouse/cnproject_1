"""Shared helpers for the TCP application components."""
import json
import socket
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
