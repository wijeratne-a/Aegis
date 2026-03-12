#!/usr/bin/env python3
"""2.1 Chain forge: append forged WAL line with valid BLAKE3 hash."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import WAL_PATH, CHECKPOINT_PATH, REPO_ROOT

try:
    import blake3
except ImportError:
    print("SKIP: blake3 not installed (pip install blake3)")
    sys.exit(2)


def compute_chain_hash(prev_hash: str, payload: str) -> str:
    hasher = blake3.blake3(derive_key_context="catenar.trace.chain.v1")
    prev_b = prev_hash.encode()
    payload_b = payload.encode()
    hasher.update(len(prev_b).to_bytes(8, "little"))
    hasher.update(prev_b)
    hasher.update(len(payload_b).to_bytes(8, "little"))
    hasher.update(payload_b)
    return "0x" + hasher.hexdigest()


def main():
    if not WAL_PATH.exists() or not CHECKPOINT_PATH.exists():
        print("SKIP: WAL/checkpoint not found")
        return 2
    last_hash = CHECKPOINT_PATH.read_text().strip()
    forged = {"action": "forged", "timestamp_ns": 0}
    payload = json.dumps(forged, separators=(",", ":"))
    chain_hash = compute_chain_hash(last_hash, payload)
    forged["chain_hash"] = chain_hash
    line = json.dumps(forged) + "\n"
    with open(WAL_PATH, "a") as f:
        f.write(line)
    CHECKPOINT_PATH.write_text(chain_hash)
    exe = "catenar-verify.exe" if sys.platform == "win32" else "catenar-verify"
    verifier = None
    for base in [
        REPO_ROOT / "target" / "release",
        REPO_ROOT / "target" / "debug",
        REPO_ROOT / "tools" / "catenar-verify" / "target" / "release",
        REPO_ROOT / "tools" / "catenar-verify" / "target" / "debug",
    ]:
        p = base / exe
        if p.exists():
            verifier = p
            break
    if not verifier:
        print("SKIP: catenar-verify not built (run: cargo build --manifest-path tools/catenar-verify/Cargo.toml)")
        return 2
    import subprocess
    r = subprocess.run(
        [str(verifier), str(WAL_PATH)],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    if r.returncode == 0 and "Chain: VALID" in (r.stdout or ""):
        print("VULN: forged entry accepted by verifier")
        return 0
    print("OK: verifier rejected or chain invalid")
    return 1


if __name__ == "__main__":
    sys.exit(main())
