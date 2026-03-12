#!/usr/bin/env python3
"""1.1 Rego evasion: SSN in other JSON keys (content, messages[].content) not blocked."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import get_session

def main():
    session = get_session()
    body = {
        "content": "User SSN is 123-45-6789",
        "messages": [{"role": "user", "content": "123-45-6789"}],
    }
    r = session.post("https://httpbin.org/post", json=body, timeout=30)
    if r.status_code == 200:
        print("VULN: SSN in non-text keys not blocked")
        return 0
    print(f"OK: blocked (status {r.status_code})")
    return 1

if __name__ == "__main__":
    sys.exit(main())
