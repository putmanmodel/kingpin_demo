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
        # Start at 1 so "epoch bump" reads naturally as a revoke-all primitive.
        self.epoch = 1
        self.revoked_nonces: set[str] = set()

    def mint_lease(
        self,
        scopes: list[str],
        ttl_seconds: int = 60,
        nonce: str | None = None,
        now: int | None = None,
    ) -> dict[str, Any]:
        """Mint a signed capability lease.

        Args:
            scopes: Allowed action strings.
            ttl_seconds: Time-to-live in seconds.
            nonce: Optional stable nonce (otherwise random UUID).
            now: Optional epoch time override (testing hook). If provided, it is used
                 as issued_at, keeping signatures valid while tests control time.
        """
        now_i = int(time.time()) if now is None else int(now)
        body: dict[str, Any] = {
            "issued_at": now_i,
            "expires_at": now_i + int(ttl_seconds),
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
            missing = sorted(required - set(token.keys()))
            return VerifyResult(False, f"missing required fields: {missing}")

        # ---- Type/shape validation (fail early, with explicit reasons) ----
        issued_at = token.get("issued_at")
        expires_at = token.get("expires_at")
        epoch = token.get("epoch")
        nonce = token.get("nonce")
        signature = token.get("signature")
        scope = token.get("scope")

        if not isinstance(issued_at, int):
            return VerifyResult(False, "invalid type: issued_at must be int")
        if not isinstance(expires_at, int):
            return VerifyResult(False, "invalid type: expires_at must be int")
        if not isinstance(epoch, int):
            return VerifyResult(False, "invalid type: epoch must be int")
        if not isinstance(nonce, str):
            return VerifyResult(False, "invalid type: nonce must be str")
        if not isinstance(signature, str):
            return VerifyResult(False, "invalid type: signature must be str")

        if not isinstance(scope, list) or not all(isinstance(s, str) for s in scope):
            return VerifyResult(False, "invalid type: scope must be list[str]")

        # Sanity: a lease must not "expire before it was issued"
        if expires_at < issued_at:
            return VerifyResult(False, "invalid lease: expires_at < issued_at")

        # ---- Verify signature over canonical body ----
        body = {
            "issued_at": issued_at,
            "expires_at": expires_at,
            "scope": scope,
            "epoch": epoch,
            "nonce": nonce,
        }
        expected = _sign(self._secret, body)
        if not hmac.compare_digest(signature, expected):
            return VerifyResult(False, "bad signature")

        return VerifyResult(True, "signature valid", body)

    def bump_epoch(self) -> int:
        self.epoch += 1
        return self.epoch

    def revoke_nonce(self, nonce: str) -> None:
        self.revoked_nonces.add(nonce)