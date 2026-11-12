# control-plane

**A charter-as-code control plane for agent institutions.**
Companion code for *The PMO Is Becoming a Control Plane* (Agent Institutions, Part 2) and *Measuring an Agent Institution* (Part 3) by Michael Shost.

Part 1 of this repository showed how to enforce *why* an agent acts, with a decision record checked at a gate before any action runs. This module builds what that gate enforces: charters that are signed, versioned, delegated, budgeted, gated, measured, and continuously reconciled.

The idea in one sentence: **delivery governance already contains the controls agents need. It has just never been executable.**

## What it implements

| Delivery discipline | Runtime primitive in this module |
|---|---|
| Project charter | Signed, content-addressed `Charter`; identity is a SHA-256 digest, not a name |
| Integrated change control | `amend()` issues a new version; the old digest stops authorizing immediately |
| Work breakdown and delegation | Child charters can only narrow actions, budget, and time |
| Stage gates | `pass_gate()` requires attested evidence plus a human signature from someone other than the owner |
| Cost baseline | Hierarchical budget envelopes with atomic escrow reservations |
| Cost control | Earned value (PV, EV, AC, CPI, SPI, EAC) computed from the ledger |
| Oversight | `reconcile()` compares declared intent with observed state and can only stop, flag, or release |
| Lessons learned | Append-only, hash-chained, tamper-evident ledger |

## The design rules

1. **Only humans charter work.** Agents hold no signing keys. An agent that tries to charter itself fails signature verification.
2. **Attestation is evidence, not authority.** Agents may report that exit criteria are met. Only an independent human passes a gate.
3. **Reserve before you spend.** Budget is escrowed atomically on the charter and every ancestor before an action runs. Allocations may be overcommitted; reservations never are.
4. **Automation may reduce authority. Only humans may grant it.** The reconciler can suspend, flag, and release. Resuming work requires a signed human act.

## Run it

Requires Python 3.10 or later. Standard library only, no installs.

```bash
python demo.py               # Part 2: nine scenarios, end to end
python demo_measurement.py   # Part 3: three agents, thirty days of evidence
python -m unittest -v        # 35 tests across both modules
```

The demo walks through delegation that cannot widen, agent self-chartering rejected, graded verdicts, change control that invalidates stale versions, stage gates with separation of duties, forty agents racing for one budget, parent suspension cascading to children, continuous earned value with reconciliation findings, tamper detection, and a timed-out action held in doubt until the system of record resolves it.

## The concurrency proof

The most common agent budget check is *check, then spend*. Under parallel agents it is a time-of-check to time-of-use race ([CWE-367](https://cwe.mitre.org/data/definitions/367.html)). The test suite reproduces it deterministically with a barrier between the check and the spend:

| Approach | Agents approved (40 x $30 against $300) | Spent |
|---|---|---|
| Naive check-then-spend | 40 | $1,200 |
| Escrow reservation | 10 | $300 |

See `TestBudgets` in `test_control_plane.py`. If your agent framework has never run this test, assume it is exposed.

## Timeouts don't release money. Evidence does. (v1.1)

What happens when an agent reserves budget, acts, then times out and never confirms whether it actually spent? Releasing the reservation on silence would reintroduce the overspend race the escrow exists to prevent. So unknown is treated as spent:

- **Idempotency key.** The reservation ID travels with the action, so a retry can never be booked twice and the outcome can be looked up later.
- **IN_DOUBT, not released.** When a reservation's lease expires, or its charter stops, it moves to `IN_DOUBT` and stays encumbered. The reconciler queries the system of record by that key, then commits at actual cost or releases only on evidence that nothing was spent.
- **Bounded exposure.** In-doubt exposure is capped per agent and per charter. An agent at its cap is denied new spend until its open outcomes are resolved.
- **Escalation.** Anything that stays unresolved escalates to the charter's accountable owner.

See scenario 9 in `demo.py` and `TestInDoubt` in `test_control_plane.py`. Thanks to Kiran Yenaganti, whose question about agents that time out mid-action prompted this revision.

## Measuring an agent institution (Part 3)

`measurement.py` answers the question every executive asks next: when do agents deserve more autonomy, and when less?

- **Measure only evidence agents cannot author.** The scorecard is computed from the hash-chained ledger and refuses to run if the chain does not verify. Outcomes the agent reports about itself are counted, but never as evidence toward trust; only outcomes confirmed by the system of record are.
- **Detect metric gaming.** Threshold hugging (pricing actions just under the approval limit, what bankers call structuring), estimates that drift below actual cost, and probing outside the charter each count against an agent.
- **Trust works like a credit limit.** Agents climb a four-tier ladder (SUPERVISED, ASSISTED, TRUSTED, DELEGATED), and each tier sets the most an agent may spend on one action before a human approves. Bad signals lower an agent's tier automatically. Raising it requires a signed human approval bound to the digest of the exact evidence it was proposed on. If new evidence lands before the approval, the approval no longer verifies.

Run `python demo_measurement.py`: a reliable agent earns a promotion, an agent pricing everything just under its limit is demoted for structuring, and an agent that probes outside its charter is demoted, all from the ledger alone.

## What this is, and is not

This is a reference implementation written for clarity, not a production library. Before production use:

- Replace HMAC with asymmetric signatures (for example Ed25519) and hardware-backed key custody.
- Replace the single in-process lock with a transactional store using serializable reservations, plus idempotent commits for retried actions.
- Replace the logical day counter with real time that tolerates clock skew and fails closed when time cannot be trusted.
- Keep the Part 1 gate, sandboxing, least-privilege tokens, and input validation. This module governs intent, authority, and money. It does not contain a compromised runtime.

## Files

| File | Purpose |
|---|---|
| `control_plane.py` | The control plane (about 440 lines) |
| `demo.py` | Part 2 scenario walkthrough |
| `test_control_plane.py` | 20 tests, including the concurrency proof and in-doubt handling |
| `measurement.py` | Part 3: scorecard, gaming detection, and the autonomy ladder (about 280 lines) |
| `demo_measurement.py` | Part 3 scenario walkthrough |
| `test_measurement.py` | 15 tests, including evidence-bound promotions |

## The series

- **Part 1:** [Every Agent Action Needs a Reason](https://lnkd.in/p/g-Gmftuz): decision provenance and enforcement at the moment of action
- **Part 2:** [The PMO Is Becoming a Control Plane](https://www.linkedin.com/pulse/pmo-becoming-control-plane-michael-shost-iprue/): charters as code, stage gates, escrowed budgets, earned value
- **Part 3:** Measuring an Agent Institution: `measurement.py` in this folder
- **Part 4:** How to Fire an Agent (coming next)

## Author

Michael Shost: enterprise architect and engineer; C|CISO and C|EH certified security leader; enterprise delivery leader. [LinkedIn](https://www.linkedin.com/in/michaelshost/)
