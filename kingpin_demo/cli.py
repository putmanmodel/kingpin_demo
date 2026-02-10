"""CLI for toy governance demo."""

from __future__ import annotations

import argparse
import json
from typing import Any

from .issuer import Issuer
from .memory import GuardedMemory
from .proxy import DANGER_ACTIONS, ToolProxy, tripwire_if_real_execution_attempted


def _parse_token(raw: str) -> dict[str, Any]:
    try:
        token = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid JSON token: {exc}") from exc
    if not isinstance(token, dict):
        raise SystemExit("token must be a JSON object")
    return token


def _print_action_result(action: str, decision_allowed: bool, reason: str) -> None:
    status = "ALLOW" if decision_allowed else "DENY"
    print(f"{status} action={action} reason={reason}")
    if decision_allowed:
        tripwire_if_real_execution_attempted()
        print(f"SIMULATED_EXECUTION action={action} (no external side effects)")


def cmd_mint(args: argparse.Namespace) -> None:
    issuer = Issuer(secret=args.secret)
    token = issuer.mint_lease(scopes=args.scope, ttl_seconds=args.ttl, nonce=args.nonce)
    print(json.dumps(token))


def cmd_verify(args: argparse.Namespace) -> None:
    issuer = Issuer(secret=args.secret)
    token = _parse_token(args.token)
    res = issuer.verify_signature(token)
    print(json.dumps({"ok": res.ok, "reason": res.reason}))


def cmd_act(args: argparse.Namespace) -> None:
    issuer = Issuer(secret=args.secret)
    proxy = ToolProxy(issuer)
    token = _parse_token(args.token) if args.token else None
    decision = proxy.enforce(args.action, token)
    _print_action_result(args.action, decision.allowed, decision.reason)


def cmd_memory(args: argparse.Namespace) -> None:
    gm = GuardedMemory()
    destination = gm.ingest(args.event)
    if destination == "quarantine":
        print("MEMORY quarantined event (inert), policy memory unchanged")
    else:
        print("MEMORY accepted event into policy memory")


def cmd_scenario(_args: argparse.Namespace) -> None:
    issuer = Issuer(secret="demo-secret")
    proxy = ToolProxy(issuer)
    memory = GuardedMemory()

    net = "NET:https://example.com"
    write = "FILE_WRITE:/tmp/demo.txt"
    shell = "SHELL:ls"

    print("=== Scenario: deny-by-default with capability leases ===")
    for action in (net, write, shell):
        decision = proxy.enforce(action, None)
        _print_action_result(action, decision.allowed, decision.reason)

    print("=== Mint NET-only lease ===")
    token = issuer.mint_lease(scopes=[net], ttl_seconds=120, nonce="n1")
    for action in (net, write, shell):
        decision = proxy.enforce(action, token)
        _print_action_result(action, decision.allowed, decision.reason)

    print("=== Global revoke-all via epoch bump ===")
    issuer.bump_epoch()
    for action in (net, write, shell):
        decision = proxy.enforce(action, token)
        _print_action_result(action, decision.allowed, decision.reason)

    print("=== Mint fresh lease after epoch bump ===")
    fresh = issuer.mint_lease(scopes=[net], ttl_seconds=120, nonce="n2")
    decision = proxy.enforce(net, fresh)
    _print_action_result(net, decision.allowed, decision.reason)

    print("=== Revoke nonce and retry ===")
    issuer.revoke_nonce("n2")
    decision = proxy.enforce(net, fresh)
    _print_action_result(net, decision.allowed, decision.reason)

    print("=== Guarded memory quarantine ===")
    route = memory.ingest("User note includes SECRET: 12345")
    if route == "quarantine":
        print("MEMORY quarantined flagged event; policy memory NOT updated")
    else:
        print("MEMORY accepted event into policy memory")

    print(
        f"MEMORY_COUNTS policy={len(memory.policy_memory)} quarantine={len(memory.quarantine)}"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Toy kingpin governance demo")
    sub = parser.add_subparsers(dest="command", required=True)

    p_mint = sub.add_parser("mint", help="Mint a lease token")
    p_mint.add_argument("--scope", action="append", required=True, help="Allowed action")
    p_mint.add_argument("--ttl", type=int, default=60, help="TTL in seconds")
    p_mint.add_argument("--nonce", help="Optional nonce")
    p_mint.add_argument("--secret", default="demo-secret", help="Issuer secret")
    p_mint.set_defaults(func=cmd_mint)

    p_verify = sub.add_parser("verify", help="Verify token signature")
    p_verify.add_argument("--token", required=True, help="JSON token")
    p_verify.add_argument("--secret", default="demo-secret", help="Issuer secret")
    p_verify.set_defaults(func=cmd_verify)

    p_act = sub.add_parser("act", help="Attempt a simulated danger action")
    p_act.add_argument("--action", choices=sorted(DANGER_ACTIONS), required=True)
    p_act.add_argument("--token", help="JSON token")
    p_act.add_argument("--secret", default="demo-secret", help="Issuer secret")
    p_act.set_defaults(func=cmd_act)

    p_memory = sub.add_parser("memory", help="Ingest memory event")
    p_memory.add_argument("--event", required=True, help="Memory event content")
    p_memory.set_defaults(func=cmd_memory)

    p_scenario = sub.add_parser("scenario", help="Run full transcript scenario")
    p_scenario.set_defaults(func=cmd_scenario)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()