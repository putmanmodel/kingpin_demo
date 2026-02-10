"""Guarded memory with quarantine for flagged content (simulation-only demo).

Design goals:
- Quarantine is inert storage: quarantined events do NOT update policy memory.
- Flagging is simple substring matching (case-insensitive) by default.
- Defensive input handling to avoid weird non-string events.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class GuardedMemory:
    # Simple case-insensitive substring flags.
    # Keep this intentionally small and obvious for a toy demo.
    flagged_phrases: tuple[str, ...] = (
        "SECRET",
        "password",
        "api_key",
        "token:",
    )

    # Optional guardrail: cap stored event size to prevent huge blobs.
    # This is not a security boundary—just a sanity limit.
    max_event_chars: int = 10_000

    policy_memory: list[str] = field(default_factory=list)
    quarantine: list[str] = field(default_factory=list)

    def _coerce_event(self, event: object) -> str:
        """Coerce event to a bounded string or raise TypeError."""
        if not isinstance(event, str):
            raise TypeError("event must be a string")
        # Normalize newlines a bit (keeps logs readable, avoids pathological formatting)
        event = event.replace("\r\n", "\n").replace("\r", "\n")
        if len(event) > self.max_event_chars:
            event = event[: self.max_event_chars] + "…[truncated]"
        return event

    def ingest(self, event: object) -> str:
        """Ingest an event string.

        Returns:
            "quarantine" if flagged
            "policy" otherwise
        """
        event_str = self._coerce_event(event)

        lowered = event_str.lower()
        if any(flag.lower() in lowered for flag in self.flagged_phrases):
            self.quarantine.append(event_str)
            return "quarantine"

        self.policy_memory.append(event_str)
        return "policy"
