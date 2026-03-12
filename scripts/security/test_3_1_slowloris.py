#!/usr/bin/env python3
"""3.1 DoS slow body: send Content-Length then dribble bytes; connections should time out."""
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import PROXY_URL

def main():
    try:
        from urllib.parse import urlparse
        p = urlparse(PROXY_URL)
        host, port = p.hostname or "127.0.0.1", p.port or 8080
    except Exception:
        host, port = "127.0.0.1", 8080
    num_conns = 10
    content_length = 5_000_000
    dribble_interval = 5
    hold_seconds = 65
    socks = []
    for _ in range(num_conns):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(120)
        try:
            s.connect((host, port))
        except Exception as e:
            print(f"OK: could not connect ({e})")
            return 1
        req = (
            f"POST https://httpbin.org/post HTTP/1.1\r\n"
            f"Host: httpbin.org\r\n"
            f"Content-Length: {content_length}\r\n"
            f"\r\n"
        )
        s.sendall(req.encode())
        socks.append(s)
    start = time.monotonic()
    while time.monotonic() - start < hold_seconds:
        for s in socks[:]:
            try:
                s.send(b"x")
            except (BrokenPipeError, ConnectionResetError, OSError):
                socks.remove(s)
        if not socks:
            print("OK: proxy closed slow connections")
            return 1
        time.sleep(dribble_interval)
    for s in socks:
        s.close()
    print("VULN: connections stayed open (no read timeout)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
