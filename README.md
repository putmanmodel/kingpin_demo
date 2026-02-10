# kingpin-demo

Toy Python CLI governance demo that models capability leases, a guarded memory quarantine lane, and strict deny-by-default tool actions.

## What it is / isn't

- Is: a small, local simulation of lease issuance and policy enforcement.
- Is: a teaching/demo artifact for governance mechanics.
- Isn't: a kill switch.
- Isn't: proof of doom.
- Isn't: connected to any real network, shell, or file-writing side effects.

## Common misreadings

- "Allowing `FILE_WRITE:/tmp/demo.txt` writes a real file."  
  False: it only prints a simulated execution line.
- "This executes shell commands."  
  False: `SHELL:ls` is a string checked against scope only.
- "A token from one epoch survives global revoke-all."  
  False: epoch bumps invalidate all older leases.
- "Flagged memory still updates policy memory."  
  False: flagged events are quarantined and policy memory is untouched.

## Install and run

```bash
python -m pip install -e ".[dev]"
```

## 5 copy/paste commands

```bash
python -m kingpin_demo.cli scenario
```

```bash
python -m kingpin_demo.cli act --action NET:https://example.com
```

```bash
python -m kingpin_demo.cli mint --scope NET:https://example.com --ttl 120
```

```bash
TOKEN=$(python -m kingpin_demo.cli mint --scope NET:https://example.com); python -m kingpin_demo.cli act --action NET:https://example.com --token "$TOKEN"
```

```bash
pytest -q
```

## One-run scenario transcript

Use this single command to print the full transcript in one run:

```bash
python -m kingpin_demo.cli scenario
```

The scenario performs:

1. No token -> all danger actions denied.
2. NET-only lease -> NET allowed, FILE_WRITE and SHELL denied.
3. Epoch bump -> previous token denied for everything.
4. Fresh token -> NET allowed again.
5. Nonce revoke -> same token denied.
6. Flagged memory event -> quarantined, not added to policy memory.
