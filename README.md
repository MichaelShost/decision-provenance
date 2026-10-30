# Decision Provenance for AI Agents

A minimal reference implementation from the article
"Every Agent Action Needs a Reason: Engineering decision provenance for agent institutions"
by Michael Shost.

Every agent action must carry a decision record that binds purpose, identity,
authority, and budget, and that record is enforced BEFORE the action runs.

## What it demonstrates
- Charters that delegate but can never widen scope or budget
- A decision gate that fails closed, with four verdicts: allow, escalate, deny, terminate
- Key-bound agent identity with revocation
- An append-only, SHA-256 hash-chained ledger that detects tampering

## Run it
Python 3.10 or later, standard library only:

    python decision_gate.py

## Note
This is a teaching sketch, not production code. In production, pair it with
isolation, least-privilege tokens, signed ledger entries, and an append-only store.

   ## The Agent Institutions series

   - **Part 1: Every Agent Action Needs a Reason.** Decision provenance and enforcement at the moment of action. Code: `decision_gate.py` (repository root).
   - **Part 2: The PMO Is Becoming a Control Plane.** Charters as code, stage gates, escrowed budgets, earned value, and reconciliation. Code: [`control-plane/`](control-plane/)
   - **Part 3: Measuring an Agent Institution.** Coming next.
