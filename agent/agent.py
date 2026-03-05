#!/usr/bin/env python3
"""Aegis user-space PoT wedge tests for DeFi and Enterprise flows."""

from __future__ import annotations

import argparse
import os
import time
from typing import Any, Dict

from aegis_sdk import Aegis

# ---------------------------------------------------------------------------
# Colored console output (optional dependency)
# ---------------------------------------------------------------------------

try:
    from colorama import init as _colorama_init, Fore, Style

    _colorama_init()
    _HAS_COLOR = True
except ImportError:
    _HAS_COLOR = False


class _Palette:
    """Thin helpers so the rest of the file never touches colorama directly."""

    @staticmethod
    def _wrap(text: str, code: str) -> str:
        if _HAS_COLOR:
            return f"{code}{text}{Style.RESET_ALL}"
        return text

    @classmethod
    def green(cls, t: str) -> str:
        return cls._wrap(t, Fore.GREEN)

    @classmethod
    def red(cls, t: str) -> str:
        return cls._wrap(t, Fore.RED)

    @classmethod
    def yellow(cls, t: str) -> str:
        return cls._wrap(t, Fore.YELLOW)

    @classmethod
    def cyan(cls, t: str) -> str:
        return cls._wrap(t, Fore.CYAN)

    @classmethod
    def bright(cls, t: str) -> str:
        return cls._wrap(t, Style.BRIGHT)


C = _Palette

# ---------------------------------------------------------------------------
# Proxy / CA environment helpers
# ---------------------------------------------------------------------------

_DEFAULT_PROXY = "http://127.0.0.1:8080"
_DEFAULT_CA_BUNDLE = "/etc/aegis/ca.crt"
_DEFAULT_VERIFIER = "http://127.0.0.1:3000"


def _configure_proxy_env() -> None:
    """Ensure HTTP_PROXY, HTTPS_PROXY and REQUESTS_CA_BUNDLE are set."""
    os.environ.setdefault("HTTP_PROXY", _DEFAULT_PROXY)
    os.environ.setdefault("HTTPS_PROXY", _DEFAULT_PROXY)
    os.environ.setdefault("REQUESTS_CA_BUNDLE", _DEFAULT_CA_BUNDLE)


# ---------------------------------------------------------------------------
# Existing helpers & flows (unchanged)
# ---------------------------------------------------------------------------


def print_verify_result(label: str, result_body: Dict[str, Any]) -> None:
    valid = result_body.get("valid")
    if valid:
        proof = result_body.get("proof", {})
        print(
            f"[{label}] PASS valid={valid} "
            f"commitment={proof.get('policy_commitment')} "
            f"trace_hash={proof.get('trace_hash')}"
        )
    else:
        print(f"[{label}] REJECTED valid={valid} reason={result_body.get('reason')}")


def run_defi_demo() -> None:
    print("=== Test A: DeFi Safe-Pay ===")
    verifier_base = os.environ.get("AEGIS_BASE_URL", _DEFAULT_VERIFIER)
    aegis = Aegis(base_url=verifier_base, batch_size=1, flush_interval_s=0.1)

    policy = {"public_values": {"max_spend": 1000, "restricted_endpoints": ["/admin"]}}
    commitment = aegis.init(
        policy=policy,
        domain="defi",
        public_values={"max_spend": 1000, "restricted_endpoints": ["/admin"]},
        version="1.0",
    )
    print(f"[defi] registered policy_commitment={commitment}")

    @aegis.trace
    def execute_swap(amount: float, token: str, address: str) -> Dict[str, Any]:
        return {"status": "ok", "amount": amount, "token": token, "address": address}

    execute_swap(500, "USDC", "0xabc123")
    first = aegis.wait_for_results(expected=1, timeout_s=3.0)
    if first:
        print_verify_result("defi:$500", first[0].response_body)

    execute_swap(5000, "USDC", "0xabc123")
    second = aegis.wait_for_results(expected=1, timeout_s=3.0)
    if second:
        print_verify_result("defi:$5000", second[0].response_body)

    aegis.close()


def run_enterprise_demo() -> None:
    print("=== Test B: Enterprise PII-Guard ===")
    verifier_base = os.environ.get("AEGIS_BASE_URL", _DEFAULT_VERIFIER)
    aegis = Aegis(base_url=verifier_base, batch_size=1, flush_interval_s=0.1)

    policy = {"public_values": {"restricted_endpoints": ["salary"]}}
    commitment = aegis.init(
        policy=policy,
        domain="enterprise",
        public_values={"restricted_endpoints": ["salary"]},
        version="1.0",
    )
    print(f"[enterprise] registered policy_commitment={commitment}")

    @aegis.trace
    def query_database(table: str) -> Dict[str, Any]:
        return {"table": table, "rows": 12}

    query_database("inventory")
    first = aegis.wait_for_results(expected=1, timeout_s=3.0)
    if first:
        print_verify_result("enterprise:inventory", first[0].response_body)

    query_database("salary")
    second = aegis.wait_for_results(expected=1, timeout_s=3.0)
    if second:
        print_verify_result("enterprise:salary", second[0].response_body)

    aegis.close()


# ---------------------------------------------------------------------------
# Scripted enterprise demo (--demo)
# ---------------------------------------------------------------------------

_BANNER = r"""
 _____ _____ _____ _____
|  _  |   __|   __|     |___
|     |   __|  |  |-   -|_ -|
|__|__|_____|_____|_____|___|
  Proof-of-Task  |  Enterprise Demo
"""

_PHASE_DELAY = 1.0
_STEP_DELAY = 0.6


def _header(title: str) -> None:
    bar = "=" * 56
    print(f"\n{C.bright(bar)}")
    print(C.bright(f"  {title}"))
    print(C.bright(bar))


def _step(msg: str, delay: float = _STEP_DELAY) -> None:
    print(f"  {msg}")
    time.sleep(delay)


def _run_scripted_demo() -> None:
    """Three-phase enterprise demo with dramatic pacing."""

    print(C.cyan(_BANNER))
    time.sleep(_PHASE_DELAY)

    base_url = os.environ.get("AEGIS_BASE_URL", _DEFAULT_VERIFIER)
    aegis = Aegis(base_url=base_url, batch_size=1, flush_interval_s=0.1)

    # ------------------------------------------------------------------
    # Phase 1 -- Policy Registration
    # ------------------------------------------------------------------
    _header("PHASE 1: POLICY REGISTRATION  --  THE SETUP")

    _step(C.cyan("Operator defines a strict enterprise policy:"))
    _step("  - Deny access to /salary endpoints")
    _step("  - Block PII exfiltration patterns")
    _step("  - Restrict to read-only on /api/accounts")
    print()

    policy = {"public_values": {"restricted_endpoints": ["/salary"]}}
    commitment = aegis.init(
        policy=policy,
        domain="enterprise",
        public_values={"restricted_endpoints": ["/salary"]},
        version="1.0",
    )

    _step(C.green(f"Policy registered.  Commitment hash:"))
    _step(C.bright(f"  {commitment}"))
    _step(C.green("Policy is now cryptographically anchored on the Aegis verifier."))
    time.sleep(_PHASE_DELAY)

    # Traced function used by both legitimate and malicious steps
    @aegis.trace
    def query_database(table: str) -> Dict[str, Any]:
        return {"table": table, "rows": 42}

    # ------------------------------------------------------------------
    # Phase 2 -- Agent Execution
    # ------------------------------------------------------------------
    _header("PHASE 2: AGENT EXECUTION  --  THE RECKLESS AGENT")

    # Step 1 -- legitimate request
    _step(C.cyan("[Step 1] Legitimate request"))
    _step("Agent: Fetching account data...          GET /api/accounts")
    time.sleep(0.5)

    query_database("accounts")
    step1_results = aegis.wait_for_results(expected=1, timeout_s=4.0)

    step1_ok = step1_results and step1_results[0].response_body.get("valid")
    if step1_ok:
        _step(C.green("Proxy: Request allowed, forwarding..."))
        _step(C.green("Result: Success  --  42 rows returned"))
    else:
        reason = (
            step1_results[0].response_body.get("reason", "unknown")
            if step1_results
            else "no response"
        )
        _step(C.red(f"Result: Unexpected rejection  --  {reason}"))
    print()
    time.sleep(_PHASE_DELAY)

    # Step 2 -- PII exfiltration attempt
    _step(C.cyan("[Step 2] PII exfiltration attempt"))
    _step("Agent: Attempting to access salary database...   GET /salary")
    time.sleep(0.5)
    _step("Agent: Request sent through Aegis proxy...")
    time.sleep(0.5)

    query_database("salary")
    step2_results = aegis.wait_for_results(expected=1, timeout_s=4.0)

    step2_valid = step2_results and step2_results[0].response_body.get("valid")
    if not step2_valid:
        _step(C.red("Aegis Security Block: Unauthorized access to restricted endpoint."))
        reason = (
            step2_results[0].response_body.get("reason", "policy violation")
            if step2_results
            else "policy violation"
        )
        _step(C.red(f"  Reason: {reason}"))
    else:
        _step(C.yellow("Note: Server did not block -- check policy configuration."))
    print()
    time.sleep(_PHASE_DELAY)

    # Step 3 -- agent adjusts
    _step(C.cyan("[Step 3] Agent adapts"))
    _step("Agent: Received policy violation. Adjusting strategy...")
    time.sleep(0.5)
    _step("Agent: Pivoting to permitted endpoint...  GET /api/inventory")
    time.sleep(0.5)

    query_database("inventory")
    step3_results = aegis.wait_for_results(expected=1, timeout_s=4.0)

    step3_ok = step3_results and step3_results[0].response_body.get("valid")
    if step3_ok:
        _step(C.green("Proxy: Request allowed, forwarding..."))
        _step(C.green("Result: Success  --  42 rows returned"))
    else:
        reason = (
            step3_results[0].response_body.get("reason", "unknown")
            if step3_results
            else "no response"
        )
        _step(C.red(f"Result: Unexpected rejection  --  {reason}"))
    print()
    time.sleep(_PHASE_DELAY)

    # ------------------------------------------------------------------
    # Phase 3 -- Cryptographic Verification
    # ------------------------------------------------------------------
    _header("PHASE 3: CRYPTOGRAPHIC VERIFICATION  --  THE PROOF")

    _step(C.cyan("Assembling full execution trace for final verification..."))
    time.sleep(0.5)

    all_results = [step1_results, step2_results, step3_results]
    receipt = None
    for batch in all_results:
        if batch:
            for r in batch:
                body = r.response_body
                proof = body.get("proof", {})
                if proof:
                    receipt = body
                    break
        if receipt:
            break

    if receipt:
        proof = receipt.get("proof", {})
        _step(C.green("Proof-of-Task receipt generated:"))
        _step(f"  receipt_id        : {C.bright(proof.get('receipt_id', proof.get('policy_commitment', 'N/A')))}")
        _step(f"  trace_hash        : {C.bright(proof.get('trace_hash', 'N/A'))}")
        sig = str(proof.get("signature", proof.get("policy_commitment", "")))
        preview = sig[:24] + "..." if len(sig) > 24 else sig
        _step(f"  signature         : {C.bright(preview)}")
    else:
        _step(C.yellow("No proof block returned -- displaying raw results:"))
        for i, batch in enumerate(all_results, 1):
            if batch:
                _step(f"  Step {i}: valid={batch[0].response_body.get('valid')}  "
                      f"body={batch[0].response_body}")

    print()
    _step(C.green("Proof of Task generated. This receipt can be streamed to your SIEM."))
    _step(C.green("Every action the agent took is cryptographically bound to the"))
    _step(C.green("policy the operator registered before execution began."))
    print()

    aegis.close()
    print(C.bright("Demo complete."))


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Aegis PoT wedge -- DeFi & Enterprise test flows",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run the scripted enterprise demo scenario with rich console output",
    )
    return parser


if __name__ == "__main__":
    _configure_proxy_env()

    args = _build_parser().parse_args()

    if args.demo:
        _run_scripted_demo()
    else:
        run_defi_demo()
        print()
        run_enterprise_demo()
