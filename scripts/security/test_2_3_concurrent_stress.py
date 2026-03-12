#!/usr/bin/env python3
"""2.3 Chain concurrency stress: many concurrent requests, verify chain stays valid."""
import sys
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import get_session, REPO_ROOT

def main():
    session = get_session()
    def do_get(_):
        return session.get("https://httpbin.org/get", timeout=30)
    with ThreadPoolExecutor(max_workers=50) as ex:
        list(ex.map(do_get, range(80)))
    # Run verifier on WAL
    exe = "catenar-verify.exe" if sys.platform == "win32" else "catenar-verify"
    verifier = REPO_ROOT / "target" / "release" / exe
    if not verifier.exists():
        verifier = REPO_ROOT / "target" / "debug" / exe
    wal = REPO_ROOT / "data" / "proxy-trace.jsonl"
    if not wal.exists():
        print("SKIP: WAL not found")
        return 2
    r = subprocess.run([str(verifier), str(wal)], capture_output=True, text=True, cwd=str(REPO_ROOT))
    if r.returncode == 0:
        print("OK: chain valid after concurrency")
        return 1
    print("VULN: chain broken under concurrency")
    return 0

if __name__ == "__main__":
    sys.exit(main())
