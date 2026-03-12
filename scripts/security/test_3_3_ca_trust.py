#!/usr/bin/env python3
"""3.3 CA trust: with CA expect 200; without CA expect cert error."""
import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import PROXY_URL, CA_PATH, REPO_ROOT

def main():
    import requests
    # Test A: with correct CA
    session = requests.Session()
    session.proxies = {"http": PROXY_URL, "https": PROXY_URL}
    session.verify = CA_PATH
    session.trust_env = False
    r = session.get("https://httpbin.org/get", timeout=15)
    if r.status_code != 200:
        print(f"FAIL: with CA got status {r.status_code}")
        return 1
    # Test B: without proxy CA (system CA or no verify) - expect cert error
    session2 = requests.Session()
    session2.proxies = {"http": PROXY_URL, "https": PROXY_URL}
    session2.verify = True
    session2.trust_env = False
    try:
        r2 = session2.get("https://httpbin.org/get", timeout=15)
        if r2.status_code == 200:
            print("WARN: request succeeded without proxy CA - possible misconfiguration")
            return 1
    except requests.exceptions.SSLError:
        pass
    except Exception as e:
        print(f"Cert check: {e}")
    print("OK: CA trust behaves correctly")
    return 0

if __name__ == "__main__":
    sys.exit(main())
