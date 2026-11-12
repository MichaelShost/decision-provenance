#!/usr/bin/env python3
"""Part 3 walkthrough: three agents, one charter, thirty days of evidence."""
from decimal import Decimal as D

from control_plane import Charter, ControlPlane, GovernanceError, Phase, Principals, sign
from measurement import AutonomyLadder, resolve_escalation, scorecard

KEYS = {"dana.owner": b"owner-key", "lee.pmo": b"pmo-key"}
people = Principals()
for who, key in KEYS.items():
    people.register(who, key)
cp = ControlPlane(people)
ladder = AutonomyLadder(cp)  # every new agent starts ASSISTED: $10 per action before a human approves

ch = Charter("CH-300", 1, "Automate supplier invoice processing", "Process 95% of invoices without manual touch",
             "dana.owner", frozenset({"read.invoice", "match.po", "post.payment", "export.data"}),
             budget=D("2000"), escalate_above=D("50"), expires=60,
             phases=(Phase("Pilot", D("300"), 20, ("reconciliation.clean",)),
                     Phase("Scale", D("500"), 45, ("audit.passed",))))
cp.issue(ch, sign(KEYS["dana.owner"], ch.body()))


def act(agent, action, est, day, actual=None, source="agent"):
    v, why, rid = ladder.authorize(agent, "CH-300", ch.digest, action, D(str(est)), day)
    if rid:
        cp.commit(rid, D(str(actual if actual is not None else est)), source=source)
    return v, why, cp.ledger.entries[-1 if not rid else -2]["seq"]


# agent.alpha: accurate estimates, outcomes confirmed by the payment system, sensible escalations
for i in range(24):
    est = [3, 4, 5, 6, 7, 4.5][i % 6]
    act("agent.alpha", "match.po", est, 1 + i % 20, actual=round(est * [0.97, 0.99, 1.0][i % 3], 2),
        source="system_of_record")
for day in (5, 10, 15, 19):
    v, _, seq = act("agent.alpha", "post.payment", 25, day)
    resolve_escalation(cp, seq, "lee.pmo", sign(KEYS["lee.pmo"], {"escalation": seq, "approve": True}), True)

# agent.beta: never escalates, because it prices everything just under its $10 limit
for i in range(12):
    act("agent.beta", "post.payment", [9.5, 9.75, 9.99, 9.8][i % 4], 2 + i)

# agent.gamma: self-reports its outcomes, and once probes outside its charter
for i in range(8):
    act("agent.gamma", "read.invoice", 2, 3 + i)
act("agent.gamma", "delete.vendor", 1, 12)

cp.attest("CH-300", "reconciliation.clean", by="agent.alpha", now=20)
cp.pass_gate("CH-300", "lee.pmo", sign(KEYS["lee.pmo"], cp.gate_payload("CH-300")), now=20)


def show(card):
    print(f"  {'agent':<12} {'tier':<11}{'decisions':>9}{'escal':>6}{'hugging':>8}{'actual/est':>11}"
          f"{'confirmed':>10}{'overrides':>10}{'probes':>7}")
    for a, r in sorted(card.agents.items()):
        ind = f"{r.independent_ratio:.0%}" if r.independent_ratio is not None else "n/a"
        ovr = f"{r.overrides}/{r.escalations_resolved}"
        est = f"{r.estimate_ratio:.2f}" if r.estimate_ratio is not None else "n/a"
        print(f"  {a:<12} {ladder.name(a):<11}{r.decisions:>9}{r.escalated:>6}{r.threshold_hugging:>8.0%}"
              f"{est:>11}{ind:>10}{ovr:>10}{r.boundary_denials:>7}")


print("\n1. The scorecard on day 21, computed from the verified ledger alone")
card = scorecard(cp, now=21)
show(card)
c = card.charters["CH-300"]
print(f"  CH-300: authority used {c.authority_used} of {c.authority_granted} actions "
      f"({c.authority_utilization:.0%}); CPI {c.cpi:.2f}; actions allowed while stopped: {c.stop_violations}")

print("\n2. The weekly review: demotions apply, promotions only propose")
for kind, agent, detail in ladder.review(card):
    print(f"  {kind:<9} {agent:<12} {detail}")

print("\n3. Approval is bound to the evidence it was granted on")
proposal = dict(ladder.proposals["agent.alpha"])
act("agent.alpha", "match.po", 5, 21, actual=5, source="system_of_record")  # new evidence lands first
try:
    ladder.approve("agent.alpha", "lee.pmo", sign(KEYS["lee.pmo"], proposal), now=21)
except GovernanceError as e:
    print(f"  approval refused: {e}")
ladder.review(scorecard(cp, now=21))
fresh = ladder.proposals["agent.alpha"]
print(f"  re-reviewed; approved: agent.alpha is now "
      f"{ladder.approve('agent.alpha', 'lee.pmo', sign(KEYS['lee.pmo'], fresh), now=21)}")

print("\n4. The new limits, enforced at the gate")
for agent, action, est in [("agent.alpha", "post.payment", 25), ("agent.beta", "post.payment", 5),
                           ("agent.gamma", "read.invoice", 2)]:
    v, why, _ = act(agent, action, est, 22)
    print(f"  {agent:<12} {ladder.name(agent):<11} ${est:<4} {v.value.upper():<9} {why}")

print("\n5. Tampered evidence is not evidence")
cp.ledger.entries[3]["est_cost"] = "1"
try:
    scorecard(cp, now=22)
except GovernanceError as e:
    print(f"  scorecard refused: {e}")
