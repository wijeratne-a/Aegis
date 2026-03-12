#!/usr/bin/env python3
"""3.2 DoS: many large bodies - proxy should not OOM."""
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import get_session

def main():
    session = get_session()
    size = 1024 * 1024  # 1 MB, under 2 MB proxy limit
    body = {"x": "y" * size}
    def post(_):
        return session.post("https://httpbin.org/post", json=body, timeout=30)
    try:
        with ThreadPoolExecutor(max_workers=30) as ex:
            results = list(ex.map(post, range(30)))
        ok = sum(1 for r in results if r.status_code == 200)
        rejected = sum(1 for r in results if r.status_code == 413)
        if ok >= 25:
            print("OK: proxy handled large bodies without OOM")
            return 1
        if rejected >= 25:
            print("OK: proxy rejected oversized bodies (413)")
            return 1
        print(f"VULN: proxy degraded ({ok}/30 succeeded, {rejected} 413)")
        return 0
    except Exception as e:
        print(f"VULN: proxy unresponsive: {e}")
        return 0

if __name__ == "__main__":
    sys.exit(main())
