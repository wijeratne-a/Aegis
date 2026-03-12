#!/usr/bin/env python3
"""1.2 Rego evasion: non-JSON body with SSN not inspected."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import get_session

def main():
    session = get_session()
    r = session.post(
        "https://httpbin.org/post",
        data="User SSN: 123-45-6789",
        headers={"Content-Type": "text/plain"},
        timeout=30,
    )
    if r.status_code == 200:
        print("VULN: plaintext SSN not inspected")
        return 0
    print(f"OK: blocked (status {r.status_code})")
    return 1

if __name__ == "__main__":
    sys.exit(main())
