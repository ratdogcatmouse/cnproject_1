#!/usr/bin/env python3
"""D1 TCP client for successful, denied, and malformed-command demonstrations."""
import argparse
import socket


def run(host, port, name, count, bad, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            stream = sock.makefile("r", encoding="utf-8")

            def send(message):
                sock.sendall((message + "\n").encode())
                answer = stream.readline()
                if not answer:
                    raise ConnectionError("connection closed")
                return answer.strip()

            if not send("HELLO " + name).startswith("OK"):
                raise ConnectionError("HELLO was not accepted")
            if bad:
                for n in range(bad):
                    send("BOGUS%d" % n)
                print("RESULT OK malformed commands sent=%d" % bad)
            else:
                for n in range(count):
                    reply = send("MSG hello-%d" % n)
                    if reply != "ECHO hello-%d" % n:
                        raise ConnectionError("unexpected response: " + reply)
                send("BYE")
                print("RESULT OK messages=%d" % count)
            return 0
    except (OSError, ConnectionError) as error:
        print("RESULT FAIL %s" % error)
        return 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("--name", default="client")
    parser.add_argument("--msgs", type=int, default=3)
    parser.add_argument("--bad", type=int, default=0)
    parser.add_argument("--timeout", type=float, default=2)
    args = parser.parse_args()
    raise SystemExit(run(args.host, args.port, args.name, args.msgs, args.bad,
                         args.timeout))


if __name__ == "__main__":
    main()
