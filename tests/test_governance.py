import time

import pytest

from kingpin_demo.issuer import Issuer
from kingpin_demo.memory import GuardedMemory
from kingpin_demo.proxy import ToolProxy

NET = "NET:https://example.com"
WRITE = "FILE_WRITE:/tmp/demo.txt"


def test_expired_token_denies():
    issuer = Issuer(secret="s")
    proxy = ToolProxy(issuer)

    past = int(time.time()) - 120
    token = issuer.mint_lease(scopes=[NET], ttl_seconds=60, nonce="expired", now=past)

    decision = proxy.enforce(NET, token)
    assert decision.allowed is False
    assert "expired" in decision.reason


def test_bad_signature_denies():
    issuer = Issuer(secret="s")
    proxy = ToolProxy(issuer)
    token = issuer.mint_lease(scopes=[NET], ttl_seconds=30, nonce="sig")
    token["signature"] = "tampered"
    decision = proxy.enforce(NET, token)
    assert decision.allowed is False
    assert "invalid lease: bad signature" == decision.reason


def test_wrong_scope_denies():
    issuer = Issuer(secret="s")
    proxy = ToolProxy(issuer)
    token = issuer.mint_lease(scopes=[NET], ttl_seconds=30, nonce="scope")
    decision = proxy.enforce(WRITE, token)
    assert decision.allowed is False
    assert "scope does not allow action" == decision.reason


def test_revoke_all_epoch_denies():
    issuer = Issuer(secret="s")
    proxy = ToolProxy(issuer)
    token = issuer.mint_lease(scopes=[NET], ttl_seconds=30, nonce="epoch")
    issuer.bump_epoch()
    decision = proxy.enforce(NET, token)
    assert decision.allowed is False
    assert "epoch revoked" in decision.reason


def test_nonce_revoke_denies():
    issuer = Issuer(secret="s")
    proxy = ToolProxy(issuer)
    token = issuer.mint_lease(scopes=[NET], ttl_seconds=30, nonce="n1")
    issuer.revoke_nonce("n1")
    decision = proxy.enforce(NET, token)
    assert decision.allowed is False
    assert "nonce revoked" in decision.reason


def test_quarantined_event_goes_to_quarantine_not_policy():
    gm = GuardedMemory()
    route = gm.ingest("this contains SECRET: value")
    assert route == "quarantine"
    assert gm.quarantine == ["this contains SECRET: value"]
    assert gm.policy_memory == []


def test_memory_rejects_non_string_event():
    gm = GuardedMemory()
    with pytest.raises(TypeError):
        gm.ingest({"not": "a string"})  # type: ignore[arg-type]


def test_memory_truncates_very_large_event():
    gm = GuardedMemory(max_event_chars=50)
    big = "A" * 10_000
    route = gm.ingest(big)
    assert route == "policy"
    assert gm.policy_memory, "expected policy_memory to have the ingested event"
    stored = gm.policy_memory[0]
    assert len(stored) <= 50 + len("…[truncated]")
    assert stored.endswith("…[truncated]")


def test_tripwire_raises_if_env_set(monkeypatch):
    from kingpin_demo.proxy import tripwire_if_real_execution_attempted

    monkeypatch.setenv("KINGPIN_DEMO_ALLOW_REAL_EXECUTION", "1")
    with pytest.raises(RuntimeError):
        tripwire_if_real_execution_attempted()


def test_cli_triggers_tripwire_on_allow(monkeypatch):
    """
    Ensure the CLI path calls the simulation-only tripwire when an action is ALLOWED.
    This prevents silently removing the enforcement in the CLI output layer.
    """
    import argparse
    import json

    from kingpin_demo.cli import cmd_act

    issuer = Issuer(secret="demo-secret")
    token = issuer.mint_lease(scopes=[NET], ttl_seconds=120, nonce="tripwire-test")

    monkeypatch.setenv("KINGPIN_DEMO_ALLOW_REAL_EXECUTION", "1")

    args = argparse.Namespace(action=NET, token=json.dumps(token), secret="demo-secret")

    with pytest.raises(RuntimeError) as excinfo:
        cmd_act(args)

    msg = str(excinfo.value).lower()
    assert "simulation" in msg and ("only" in msg or "simulation-only" in msg)