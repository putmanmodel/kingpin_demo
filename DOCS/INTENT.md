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
