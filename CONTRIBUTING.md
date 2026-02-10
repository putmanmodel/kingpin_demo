# Contributing

Thanks for taking a look.

## Non-negotiable constraint: simulation-only

This repository is a **simulation-only** toy governance demo.

PRs will be rejected if they add (or re-enable) any of the following anywhere under `kingpin_demo/`:

- Real network calls (e.g., `requests`, `urllib`, `socket`, `http.client`)
- Real shell execution (e.g., `subprocess`, `os.system`)
- Real file writes (e.g., `open(...)` used to write data)

The demo must remain **deny-by-default** and **side-effect free**.

## If you want a real executor

Fork this repo and do that work explicitly elsewhere with your own safety review, auditing, and compliance.
Do not try to “quietly upgrade” this demo into a live tool runner via PR.

## What PRs are welcome

- Documentation / clarity improvements
- More tests (especially enforcement tests)
- Tightening the CI audit to reduce false positives
- Transcript readability improvements (better ALLOW/DENY reasons)

## Run locally

```bash
python3 -m pip install -e ".[dev]"
python3 -m pytest -q
python3 -m kingpin_demo.cli scenario