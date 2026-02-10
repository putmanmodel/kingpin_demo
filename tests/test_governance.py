import time

from kingpin_demo.issuer import Issuer
from kingpin_demo.memory import GuardedMemory
from kingpin_demo.proxy import ToolProxy


NET = "NET:https://example.com"
WRITE = "FILE_WRITE:/tmp/demo.txt"


def test_expired_token_denies():
    issuer = Issuer(secret="s")
    proxy = ToolProxy(issuer)
    token = issuer.mint_lease(scopes=[NET], ttl_seconds=-1, nonce="expired")
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
