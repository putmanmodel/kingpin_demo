"""Issuer for short-lived capability tokens (leases)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
import uuid
from dataclasses import dataclass
from typing import Any


def _canonical_json(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sign(secret: bytes, payload: dict[str, Any]) -> str:
    digest = hmac.new(secret, _canonical_json(payload), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii")


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    reason: str
    payload: dict[str, Any] | None = None


class Issuer:
    """Only signer and verifier of capability leases."""

    def __init__(self, secret: str | None = None) -> None:
        self._secret = (secret or secrets.token_urlsafe(32)).encode("utf-8")
        self.epoch = 0
        self.revoked_nonces: set[str] = set()

    def mint_lease(
        self, scopes: list[str], ttl_seconds: int = 60, nonce: str | None = None
    ) -> dict[str, Any]:
        now = int(time.time())
        body = {
            "issued_at": now,
            "expires_at": now + ttl_seconds,
            "scope": sorted(set(scopes)),
            "epoch": self.epoch,
            "nonce": nonce or str(uuid.uuid4()),
        }
        token = dict(body)
        token["signature"] = _sign(self._secret, body)
        return token

    def verify_signature(self, token: dict[str, Any]) -> VerifyResult:
        required = {"issued_at", "expires_at", "scope", "epoch", "nonce", "signature"}
        if not required.issubset(token):
            return VerifyResult(False, "missing required fields")

        body = {
            "issued_at": token["issued_at"],
            "expires_at": token["expires_at"],
            "scope": token["scope"],
            "epoch": token["epoch"],
            "nonce": token["nonce"],
        }
        expected = _sign(self._secret, body)
        if not hmac.compare_digest(token["signature"], expected):
            return VerifyResult(False, "bad signature")
        return VerifyResult(True, "signature valid", body)

    def bump_epoch(self) -> int:
        self.epoch += 1
        return self.epoch

    def revoke_nonce(self, nonce: str) -> None:
        self.revoked_nonces.add(nonce)
