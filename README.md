# kingpin-demo

A toy Python CLI governance demo that models:

- **Capability leases** (short-lived, scoped tokens) enforced by a **ToolProxy**
- A **global revoke-all** mechanism (issuer epoch bump)
- **Per-token nonce revocation**
- **Guarded memory quarantine** (flagged memory is stored inertly and does not update policy memory)
- **Strict deny-by-default** for “danger-shaped” actions

This is meant to make mitigation mechanisms discussable in concrete terms — not as vibes.

---

## What it is / isn’t

**It is:**
- A small, local simulation of lease issuance + policy enforcement.
- A teaching/demo artifact for capability gating and memory quarantine.
- A concrete way to say: “If you think this is naive, propose a better mechanism and show your design.”

**It is not:**
- A “kill switch.”
- Proof of doom.
- A security product.
- A real tool runner (no network calls, no shell execution, no real file writes).
- A system that can “turn AI off.” It only demonstrates **one-way de-escalation / capability shedding** patterns.

---

## Ethical use note

This is a toy governance model meant for safety discussion and capability de-escalation.
Do not use it to build surveillance, coercion, weaponization, or systems that remove user autonomy.
If you adapt this for real tool execution, you assume full responsibility for safety, auditing, and legal compliance.

---

## Safety & side-effects (read this once)

This repo intentionally does **not** perform external actions.

- `NET:https://example.com` is a **string**, not a real request.
- `SHELL:ls` is a **string**, not a shell command.
- `FILE_WRITE:/tmp/demo.txt` does **not** create a file.

When a lease allows an action, the CLI prints:

`SIMULATED_EXECUTION ... (no external side effects)`

That’s the whole point.

---

## Common misreadings

- “Allowing `FILE_WRITE:/tmp/demo.txt` writes a real file.”
  - False — it only prints a simulated execution line.

- “This executes shell commands.”
  - False — `SHELL:ls` is never executed; it is checked against scope only.

- “A token from one epoch survives global revoke-all.”
  - False — epoch bumps invalidate all older leases immediately.

- “Flagged memory still updates policy memory.”
  - False — flagged events go to quarantine and policy memory stays untouched.

- “This design is ‘god mode’ control.”
  - No — it’s deliberately the opposite: **capability shedding**, deny-by-default, and audit-shaped transcripts.

---

## Quick start

### Install (editable) + dev deps
```bash
python3 -m pip install -e ".[dev]"
```

### Run the one-shot scenario transcript
```bash
python3 -m kingpin_demo.cli scenario
```

### Run tests
```bash
python3 -m pytest -q
```

---

## 5 copy/paste commands

### 1) Full scenario transcript (recommended first)
```bash
python3 -m kingpin_demo.cli scenario
```

### 2) Try a danger action with no token (deny-by-default)
```bash
python3 -m kingpin_demo.cli act --action NET:https://example.com
```

### 3) Mint a NET-only lease (prints a token)
```bash
python3 -m kingpin_demo.cli mint --scope NET:https://example.com --ttl 120
```

### 4) Use the token to ALLOW NET (still denies others)
```bash
TOKEN=$(python3 -m kingpin_demo.cli mint --scope NET:https://example.com --ttl 120)
python3 -m kingpin_demo.cli act --action NET:https://example.com --token "$TOKEN"
```

### 5) Run tests
```bash
python3 -m pytest -q
```

---

## What the scenario demonstrates

The `scenario` command runs a single printed transcript showing:

1. **No token → deny** all danger-shaped actions (default state).
2. **NET-only lease → allow NET**, deny FILE_WRITE and SHELL due to scope.
3. **Epoch bump → revoke-all**, previous token denied for everything.
4. **Fresh token → allow again** (only if minted after bump).
5. **Nonce revoke → deny** that token.
6. **Flagged memory event → quarantine**, policy memory not updated.

---

## Design note (plain language)

This toy model borrows a shape you see in robust systems:

- avoid single points of failure
- use short-lived, scoped permissions
- compartmentalize risky inputs (quarantine)
- make “containment” easy and “power escalation” hard

If you think this is naive, show a better mechanism — with the same constraints:
**deny-by-default, no side effects, and verifiable transcripts.**

- License: PolyForm Noncommercial 1.0.0 (no commercial use).
- Intent: See `DOCS/INTENT.md` (constraints and anti-misread guardrails).
