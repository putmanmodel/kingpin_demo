"""Guarded memory with quarantine for flagged content."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class GuardedMemory:
    flagged_phrases: tuple[str, ...] = (
        "SECRET",
        "password",
        "api_key",
        "token:",
    )
    policy_memory: list[str] = field(default_factory=list)
    quarantine: list[str] = field(default_factory=list)

    def ingest(self, event: str) -> str:
        lowered = event.lower()
        if any(flag.lower() in lowered for flag in self.flagged_phrases):
            self.quarantine.append(event)
            return "quarantine"
        self.policy_memory.append(event)
        return "policy"
