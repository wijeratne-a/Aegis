# Catenar Security Audit Tests

Runs malicious and stress tests against the proxy to confirm vulnerabilities.

## Prerequisites

- `docker compose up -d verifier proxy`
- Repo root: `./deploy/certs/ca.crt` exists
- For tests 2.1, 2.2: `./data/proxy-trace.jsonl` exists (run one request through proxy first)

## Run

```bash
cd /path/to/repo
pip install -r scripts/security/requirements.txt   # blake3, requests
python scripts/security/run_all.py
```

Or run individual tests:

```bash
python scripts/security/test_1_1_ssn_json_paths.py
```

## Exit Code Convention

| Test | Exit 0 | Exit 1 | Exit 2 |
|------|--------|--------|--------|
| 1.1, 1.2, 1.3, 3.1, 3.2 | Vulnerability (attack succeeded) | No vulnerability | - |
| 2.1, 2.2 | Vulnerability | No vulnerability | Skipped (prereq missing) |
| 2.3 | Chain broken (unexpected) | Chain valid (expected) | - |
| 3.3 | Correct behavior (no CA fails) | Misconfiguration risk | - |

## Results

`run_all.py` writes `scripts/security/results.txt` with per-test outcomes.
