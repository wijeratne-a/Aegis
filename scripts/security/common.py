"""
Shared helpers for Catenar security audit tests.
Convention: exit 0 = vulnerability confirmed (attack succeeded); non-zero = no vuln or test error.
"""
from __future__ import annotations

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
PROXY_URL = os.environ.get("SECURITY_PROXY_URL", "http://127.0.0.1:8080")
CA_PATH = os.environ.get("SECURITY_CA_PATH") or str(REPO_ROOT / "deploy" / "certs" / "ca.crt")
WAL_PATH = REPO_ROOT / "data" / "proxy-trace.jsonl"
CHECKPOINT_PATH = REPO_ROOT / "data" / "proxy-trace.jsonl.chain_checkpoint"


def get_session():
    """Return requests session with proxy and CA for HTTPS."""
    import requests
    session = requests.Session()
    session.proxies = {"http": PROXY_URL, "https": PROXY_URL}
    ca = Path(CA_PATH)
    session.verify = str(ca.resolve()) if ca.exists() else True
    session.trust_env = False
    return session


def wal_exists():
    return WAL_PATH.exists()


def checkpoint_exists():
    return CHECKPOINT_PATH.exists()
