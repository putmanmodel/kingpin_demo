"""Toy governance demo package (simulation-only)."""

from __future__ import annotations

SIMULATION_ONLY = True

__all__ = ["SIMULATION_ONLY", "Issuer", "GuardedMemory", "ToolProxy"]

from .issuer import Issuer
from .memory import GuardedMemory
from .proxy import ToolProxy
