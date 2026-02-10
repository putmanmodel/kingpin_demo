"""Tool proxy that enforces capability leases for simulated danger actions."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any

from .issuer import Issuer


def tripwire_if_real_execution_attempted() -> None:
    """Tripwire to keep this repo simulation-only.

    Activates ONLY if:
      KINGPIN_DEMO_ALLOW_REAL_EXECUTION=1
    """
    if os.getenv("KINGPIN_DEMO_ALLOW_REAL_EXECUTION") == "1":
        raise RuntimeError(
            "Tripwire: simulation-only demo. Refusing to proceed.\n"
            "You set KINGPIN_DEMO_ALLOW_REAL_EXECUTION=1.\n"
            "If you are converting this into a real executor, you must deliberately remove/modify "
            "this tripwire and assume full responsibility for safety, auditing, and compliance."
        )


DANGER_ACTIONS = {
    "NET:https://example.com",
    "FILE_WRITE:/tmp/demo.txt",
    "SHELL:ls",
}


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


class ToolProxy:
    """Enforce signature, expiry, revocation, and scope checks."""

    def __init__(self, issuer: Issuer) -> None:
        self.issuer = issuer

    def enforce(self, action: str, token: dict[str, Any] | None = None) -> Decision:
        if action not in DANGER_ACTIONS:
            return Decision(False, f"action '{action}' is unknown and denied by default")

        if token is None:
            return Decision(False, "no lease provided (deny-by-default)")

        verify = self.issuer.verify_signature(token)
        if not verify.ok:
            return Decision(False, f"invalid lease: {verify.reason}")

        payload = verify.payload or {}
        now = int(time.time())

        if int(payload["expires_at"]) < now:
            return Decision(False, "lease expired")

        if int(payload["epoch"]) != self.issuer.epoch:
            return Decision(False, "lease epoch revoked by global bump")

        nonce = str(payload["nonce"])
        if nonce in self.issuer.revoked_nonces:
            return Decision(False, "lease nonce revoked")

        scope = set(payload["scope"])
        if action not in scope:
            return Decision(False, "scope does not allow action")

        return Decision(True, "lease valid and scope allows action")


__all__ = ["ToolProxy", "Decision", "DANGER_ACTIONS", "tripwire_if_real_execution_attempted"]