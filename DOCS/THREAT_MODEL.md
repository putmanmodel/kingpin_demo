# Threat Model (Toy / Simulation-Only)

This document is intentionally short. It exists to prevent bad-faith or confused interpretations.

## What this demo *is*
- A toy model of **capability gating** (leases) + **goal-guarded memory quarantine**
- A way to discuss mitigation mechanisms concretely, with explainable ALLOW/DENY transcripts
- Simulation-only by design (tripwire + tests enforce this constraint)

## What this demo *is not*
- Not a “kill switch”
- Not a deployment-ready security system
- Not an execution framework (no real network/shell/file writes)

## Attacker / misuse assumptions (out of scope here)
- Anyone can fork and remove constraints. This demo does not prevent that.
- This repo intentionally avoids “how to operationalize” guidance.

## Threats this demo helps illustrate
- **Over-privileged agents**: deny-by-default + scoped leases reduce ambient power
- **Stale authorization**: TTL + epoch bump revokes old authority quickly
- **Partial compromise**: nonce revoke demonstrates targeted invalidation
- **Policy contamination**: quarantine lane blocks flagged events from updating policy memory

## Threats this demo does *not* solve
- Social engineering / prompt injection in general
- Model exfiltration, data poisoning, or supply-chain attacks
- Insider threats / coercion against the issuer
- Real-world tool misuse (because we intentionally do not execute tools)

## Design intent
If you remove the simulation-only constraints, you are no longer demonstrating the same mechanism.
