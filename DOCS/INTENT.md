# Intent & Constraints (Toy Governance Demo)

This project is a toy model for discussing safety mechanisms concretely.

Hard constraints (by design):
- Deny-by-default for all “danger-shaped” actions
- Capability shedding only (no “god mode” control narrative)
- No real network calls
- No shell execution
- No real file writes
- All “actions” are strings; allowed actions print SIMULATED_EXECUTION only
- Quarantined memory is inert storage and does not update policy memory
- Transcripts must explain ALLOW/DENY reasons clearly

If you fork this and remove these constraints, you are no longer demonstrating the same mechanism.

# Intent & Constraints (Toy Governance Demo)

This project is a **toy model** for discussing safety mechanisms concretely. It is designed to be easy to read, easy to run, and hard to misinterpret.

## Non‑negotiable constraints (by design)

- **Deny-by-default** for all “danger-shaped” actions.
- **Capability shedding only** (de-escalation). No “god mode” narrative.
- **No real network calls.**
- **No shell execution.**
- **No real file writes.**
- All “actions” are **strings**; allowed actions print **`SIMULATED_EXECUTION`** only.
- **Guarded memory quarantine:** flagged events are stored inertly and **do not** update policy memory.
- Transcripts must explain **ALLOW/DENY** decisions with clear reasons.

## Enforcement (so this stays simulation‑only)

- A **tripwire** exists that raises if `KINGPIN_DEMO_ALLOW_REAL_EXECUTION=1`.
- A **pytest** test asserts the tripwire raises when that env var is set.

This is intentional: converting this demo into a real executor should require explicit, visible work.

## If you fork this

If you remove or weaken any of the constraints above, you are no longer demonstrating the same mechanism.

If you still proceed, you assume full responsibility for safety, auditing, legal compliance, and downstream misuse.