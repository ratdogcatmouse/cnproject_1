#!/usr/bin/env python3
"""Firewall admin tool (talks to the controller control channel).

  fwctl.py status | reset | mode static|dynamic | unblock IP
  fwctl.py --host 10.0.0.100 status    (from a Mininet host: will be rejected)
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app"))
from common import CONTROL_PORT, request


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["status", "reset", "mode", "unblock"])
    ap.add_argument("arg", nargs="?")
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()
    req = {"cmd": args.cmd.upper()}
    if args.cmd == "mode":
        req["mode"] = args.arg
    elif args.cmd == "unblock":
        req["src"] = args.arg
    reply = request(args.host, CONTROL_PORT, req)
    print(json.dumps(reply, indent=2))
    raise SystemExit(0 if reply.get("ok") else 1)


if __name__ == "__main__":
    main()
