"""Bounded private resolver subprocess used by :mod:`mercury.resolver`."""

from __future__ import annotations

import json
import socket
import sys


def main() -> int:
    if len(sys.argv) != 2 or not sys.argv[1] or len(sys.argv[1]) > 253:
        return 2
    try:
        rows = socket.getaddrinfo(sys.argv[1], None, type=socket.SOCK_STREAM)
    except OSError:
        print("[]")
        return 1
    addresses = []
    for row in rows[:1025]:
        if len(row) == 5 and isinstance(row[4], tuple) and row[4]:
            addresses.append(row[4][0])
    print(json.dumps(addresses, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
