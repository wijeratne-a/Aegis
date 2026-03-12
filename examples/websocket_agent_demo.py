#!/usr/bin/env python3
"""
WebSocket demo: Connect to a public echo server through the Catenar proxy.

Proves the proxy successfully tunnels WebSocket (Upgrade: websocket) traffic.
Run with proxy up: docker compose up -d verifier proxy

  HTTP_PROXY=http://127.0.0.1:8080 HTTPS_PROXY=http://127.0.0.1:8080 \\
  SSL_CERT_FILE=./deploy/certs/ca.crt python examples/websocket_agent_demo.py

Or from repo root with CATENAR_DEMO=1 or after running scripts/ensure-policy.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

_root = Path(__file__).resolve().parent.parent


def _configure_env() -> None:
    """Set proxy and CA env so WebSocket connects through Catenar proxy."""
    if "HTTP_PROXY" not in os.environ and "http_proxy" not in os.environ:
        os.environ["HTTP_PROXY"] = "http://127.0.0.1:8080"
    if "HTTPS_PROXY" not in os.environ and "https_proxy" not in os.environ:
        os.environ["HTTPS_PROXY"] = "http://127.0.0.1:8080"
    no_proxy = os.environ.get("NO_PROXY", "") or os.environ.get("no_proxy", "")
    if "127.0.0.1" not in no_proxy and "localhost" not in no_proxy:
        os.environ["NO_PROXY"] = "127.0.0.1,localhost" + (f",{no_proxy}" if no_proxy else "")
    ca_path = _root / "deploy" / "certs" / "ca.crt"
    if ca_path.exists() and "SSL_CERT_FILE" not in os.environ:
        os.environ["SSL_CERT_FILE"] = str(ca_path)
        os.environ["REQUESTS_CA_BUNDLE"] = str(ca_path)


async def main() -> None:
    _configure_env()

    try:
        import websockets
    except ImportError:
        print("Install websockets: pip install websockets", file=sys.stderr)
        sys.exit(1)

    # Use default SSL context (picks up SSL_CERT_FILE from env) so we trust proxy's CA
    uri = "wss://echo.websocket.org"
    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or "http://127.0.0.1:8080"

    try:
        async with websockets.connect(
            uri,
            ssl=True,
            proxy=proxy,
            close_timeout=2,
            open_timeout=10,
        ) as ws:
            messages = [
                "Agent thought: checking weather API",
                "Agent thought: validating response",
                "Agent thought: done",
            ]
            for msg in messages:
                await ws.send(msg)
                reply = await ws.recv()
                if reply == msg:
                    print(f"  Echo OK: {msg[:40]}...")
                else:
                    print(f"  Mismatch: sent {msg!r}, got {reply!r}")
                    sys.exit(1)
        print("PASS: WebSocket echoed through Catenar proxy")
    except Exception as e:
        print(f"FAIL: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
