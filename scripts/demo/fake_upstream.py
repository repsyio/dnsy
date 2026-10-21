#!/usr/bin/env python3
"""A tiny UDP upstream for the demo: answers every A query with 198.51.100.x and every AAAA with a
2001:db8:: address derived from the name; names starting with "nx" get NXDOMAIN. Stdlib only.

usage: fake_upstream.py <port>   (binds 127.0.0.1)
"""
import socket
import struct
import sys
import zlib


def answer(query: bytes) -> bytes | None:
    if len(query) < 17:
        return None
    ident, _flags, qd = struct.unpack("!HHH", query[:6])
    pos = 12
    labels = []
    while query[pos]:
        n = query[pos]
        labels.append(query[pos + 1 : pos + 1 + n].decode("ascii", "replace"))
        pos += n + 1
    qtype = struct.unpack("!H", query[pos + 1 : pos + 3])[0]
    question = query[12 : pos + 5]
    name = ".".join(labels).lower()
    h = zlib.crc32(name.encode())
    nx = name.startswith("nx")
    flags = 0x8180 | (3 if nx else 0)
    head = struct.pack("!HHHHHH", ident, flags, 1, 0 if nx or qtype not in (1, 28) else 1, 0, 0)
    out = head + question
    if nx or qtype not in (1, 28):
        return out
    if qtype == 1:
        rdata = bytes([198, 51, 100, h % 250 + 1])
    else:
        rdata = bytes.fromhex("20010db8") + h.to_bytes(4, "big") + bytes(8)
    return out + b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 300, len(rdata)) + rdata


def main() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", int(sys.argv[1])))
    while True:
        data, peer = sock.recvfrom(4096)
        reply = answer(data)
        if reply:
            sock.sendto(reply, peer)


if __name__ == "__main__":
    main()
