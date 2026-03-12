#!/usr/bin/env python3
"""2.2 Ambiguous last line: inject duplicate earlier line; fixed load_last_hash should reject it."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import WAL_PATH, REPO_ROOT

TAIL_BYTES = 64 * 1024

try:
    import blake3
except ImportError:
    print("SKIP: blake3 not installed")
    sys.exit(2)


def compute_chain_hash(prev_hash: str, payload: str) -> str:
    h = blake3.blake3(derive_key_context="catenar.trace.chain.v1")
    pb, pl = prev_hash.encode(), payload.encode()
    h.update(len(pb).to_bytes(8, "little"))
    h.update(pb)
    h.update(len(pl).to_bytes(8, "little"))
    h.update(pl)
    return "0x" + h.hexdigest()


def payload_from_value(obj: dict) -> str:
    copy = {k: v for k, v in obj.items() if k != "chain_hash"}
    return json.dumps(copy, separators=(",", ":"))


def load_last_hash_fixed(content: bytes) -> str:
    """Simulate fixed load_last_hash: last line by offset, validate chain, reject tampered."""
    tail = content[-TAIL_BYTES:] if len(content) > TAIL_BYTES else content
    text = tail.decode("utf-8", errors="replace").rstrip("\n")
    last_nl = text.rfind("\n")
    last_line = (text[last_nl + 1 :] if last_nl >= 0 else text).strip()
    if not last_line:
        return ""
    try:
        last_val = json.loads(last_line)
    except json.JSONDecodeError:
        return ""
    last_hash = last_val.get("chain_hash")
    if not isinstance(last_hash, str):
        return ""
    last_payload = payload_from_value(last_val)
    before_last = text[:last_nl] if last_nl >= 0 else ""
    prev_nl = before_last.rfind("\n")
    prev_line = (before_last[prev_nl + 1 :] if prev_nl >= 0 else before_last).strip()
    if prev_line:
        try:
            prev_val = json.loads(prev_line)
            prev_hash = prev_val.get("chain_hash")
            if isinstance(prev_hash, str):
                expected = compute_chain_hash(prev_hash, last_payload)
                if expected != last_hash:
                    return prev_hash
        except json.JSONDecodeError:
            pass
    return last_hash


def main():
    if not WAL_PATH.exists():
        print("SKIP: WAL not found")
        return 2
    content = WAL_PATH.read_bytes()
    lines = [ln for ln in content.decode("utf-8", errors="replace").splitlines() if ln.strip()]
    if len(lines) < 2:
        print("SKIP: need at least 2 WAL lines")
        return 2
    last_line = json.loads(lines[-1])
    true_last_hash = last_line.get("chain_hash")
    if not true_last_hash:
        print("SKIP: last line has no chain_hash")
        return 2
    earlier = json.loads(lines[0])
    dup = json.dumps(earlier, separators=(",", ":")) + "\n"
    with open(WAL_PATH, "ab") as f:
        f.write(dup.encode())
    new_content = WAL_PATH.read_bytes()
    got = load_last_hash_fixed(new_content)
    if got == true_last_hash:
        print("OK: load_last_hash rejected tampered line, returned correct hash")
        return 1
    print("VULN: load_last_hash returned wrong hash (ambiguous last line)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
