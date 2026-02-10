# Architecture (Toy Governance Demo)

## Data flow

User/Agent
  |
  |  action string + optional token (lease)
  v
CLI (kingpin_demo/cli.py)
  |
  v
ToolProxy (kingpin_demo/proxy.py)
  |
  |-- deny-by-default if action unknown OR no token
  |-- verify signature
  |-- check expires_at (TTL)
  |-- check epoch == issuer.epoch (global revoke-all)
  |-- check nonce not revoked
  |-- check action in scope
  v
ALLOW/DENY transcript (SIMULATED_EXECUTION only)

## Issuer responsibilities

Issuer (kingpin_demo/issuer.py)
  - mint_lease(scopes, ttl, nonce)
  - bump_epoch()  -> invalidates all older tokens
  - revoke_nonce(nonce)

## Memory lane

GuardedMemory (kingpin_demo/memory.py)
  - ingest(event) -> "policy" OR "quarantine"
  - quarantined items are inert and do not affect policy memory
