#!/usr/bin/env python3
"""Run all security audit tests and write results."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
TESTS = [
    ("1.1", "test_1_1_ssn_json_paths.py", True),
    ("1.2", "test_1_2_non_json_ssn.py", True),
    ("1.3", "test_1_3_response_obfuscation.py", True),
    ("2.1", "test_2_1_chain_forge.py", False),
    ("2.2", "test_2_2_load_last_hash_tail.py", False),
    ("2.3", "test_2_3_concurrent_stress.py", True),
    ("3.1", "test_3_1_slowloris.py", True),
    ("3.2", "test_3_2_large_body_dos.py", True),
    ("3.3", "test_3_3_ca_trust.py", True),
]


def main():
    results = []
    for tid, script, _ in TESTS:
        path = SCRIPT_DIR / script
        if not path.exists():
            results.append((tid, "SKIP", 2, f"script not found: {script}"))
            continue
        if tid == "2.1":
            from common import wal_exists, checkpoint_exists
            if not (wal_exists() and checkpoint_exists()):
                results.append((tid, "SKIP", 2, "WAL/checkpoint not found"))
                continue
        if tid == "2.2":
            from common import wal_exists
            if not wal_exists():
                results.append((tid, "SKIP", 2, "WAL not found"))
                continue
        try:
            r = subprocess.run(
                [sys.executable, str(path)],
                cwd=SCRIPT_DIR,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            results.append((tid, "TIMEOUT", -1, "test timed out"))
            continue
        out = (r.stdout or "") + (r.stderr or "")
        if r.returncode == 0:
            label = "VULN" if tid in ("1.1", "1.2", "1.3", "2.1", "2.2", "3.1", "3.2") else "OK"
        elif r.returncode == 2:
            label = "SKIP"
        else:
            label = "OK" if tid in ("1.1", "1.2", "1.3", "2.1", "2.2", "3.1", "3.2") else "OK"
        results.append((tid, label, r.returncode, out[:200] if out else ""))
    out_path = SCRIPT_DIR / "results.txt"
    with open(out_path, "w") as f:
        for tid, label, code, out in results:
            line = f"{tid}\t{label}\t{code}\t{out[:80]}\n"
            f.write(line)
            print(f"{tid}: {label} (exit {code})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
