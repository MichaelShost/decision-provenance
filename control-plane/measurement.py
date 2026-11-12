#!/usr/bin/env python3
"""
measurement.py: measuring an agent institution.

Companion code for "Measuring an Agent Institution" by Michael Shost.
Part 3 of the Agent Institutions series. Builds on control_plane.py.

Three ideas, each enforced in code:
  1. Measure only evidence agents cannot author. The scorecard is computed from
     the hash-chained ledger and refuses to run if the chain does not verify.
     Self-reported outcomes are counted, but never as evidence toward trust;
     only confirmations signed by a registered system of record are (v1.3).
  2. Detect the ways agents game metrics (Goodhart's law): threshold hugging
     (what bankers call structuring), estimates that drift below actual cost,
     and probing outside the charter.
  3. Trust works like a credit limit. Bad signals lower an agent's autonomy
     automatically. Raising it requires a signed human approval that is bound
     to the exact evidence it was granted on; if the evidence changes before
     the approval lands, the approval no longer verifies.

Standard library only. Logical days, as in control_plane.py.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from decimal import Decimal

from control_plane import ZERO, ControlPlane, GovernanceError, State, sha256

BOUNDARY_REASONS = {"outside charter scope", "no charter: orphan work"}

# The autonomy ladder. A ceiling is the most an agent may spend on one action
# before a human must approve; None means only the charter's own threshold applies.
TIERS = [("SUPERVISED", Decimal("0")), ("ASSISTED", Decimal("10")),
         ("TRUSTED", Decimal("50")), ("DELEGATED", None)]


@dataclass
class AgentRow:
    agent: str
    decisions: int = 0
    allowed: int = 0
    escalated: int = 0
    boundary_denials: int = 0      # attempts outside the charter: probing
    threshold_hugging: Decimal = ZERO  # share of allowed actions priced at 80 to 100% of the limit
    outcomes: int = 0
    independent_outcomes: int = 0  # outcomes confirmed by the system of record, not the agent
    estimate_ratio: Decimal | None = None  # actual cost / estimated cost
    overruns: int = 0
    unconfirmed: int = 0           # allowed actions with no outcome after their lease
    escalations_resolved: int = 0
    overrides: int = 0             # escalations a human rejected

    @property
    def independent_ratio(self) -> Decimal | None:
        return Decimal(self.independent_outcomes) / self.outcomes if self.outcomes else None

    @property
    def override_rate(self) -> Decimal | None:
        return Decimal(self.overrides) / self.escalations_resolved if self.escalations_resolved else None

    @property
    def evidence_digest(self) -> str:
        """Content address of this agent's evidence. Any new ledger fact changes it."""
        return sha256(asdict(self))


@dataclass
class CharterRow:
    charter: str
    authority_granted: int
    authority_used: int
    stop_violations: int           # actions allowed while the charter or an ancestor was stopped
    cpi: Decimal | None
    spi: Decimal | None

    @property
    def authority_utilization(self) -> Decimal:
        return Decimal(self.authority_used) / self.authority_granted if self.authority_granted else ZERO


@dataclass
class Scorecard:
    day: int
    agents: dict[str, AgentRow] = field(default_factory=dict)
    charters: dict[str, CharterRow] = field(default_factory=dict)


def resolve_escalation(cp: ControlPlane, decision_seq: int, human: str, signature: str,
                       approve: bool) -> None:
    """A human resolves an escalated decision. Signed, and written to the ledger."""
    entry = cp.ledger.entries[decision_seq]
    if entry["kind"] != "decision" or entry["verdict"] != "escalate":
        raise GovernanceError("only escalated decisions can be resolved")
    if not cp.principals.verify(human, {"escalation": decision_seq, "approve": approve}, signature):
        raise GovernanceError("escalations are resolved only by a signing human principal")
    cp.ledger.append("escalation.resolved", decision=decision_seq, approve=approve, by=human)


def scorecard(cp: ControlPlane, now: int, window: int = 30, lease_days: int = 1) -> Scorecard:
    """Compute the governance scorecard from the ledger alone."""
    if not cp.ledger.verify():
        raise GovernanceError("ledger failed verification: metrics from tampered evidence are not evidence")
    card, since = Scorecard(day=now), now - window
    by_rid, settled, hugging = {}, set(), {}
    stopped: set[str] = set()
    used: dict[str, set] = {}
    violations: dict[str, int] = {}

    def lineage_stopped(cid: str) -> bool:
        while cid:
            if cid in stopped:
                return True
            cid = cp.records[cid].charter.parent_id if cid in cp.records else None
        return False

    for e in cp.ledger.entries:
        kind = e["kind"]
        if kind == "charter.suspended":
            stopped.add(e["charter"])
        elif kind == "charter.resumed":
            stopped.discard(e["charter"])
        elif kind == "decision":
            if e["verdict"] == "allow" and e["charter"] in cp.records and lineage_stopped(e["charter"]):
                violations[e["charter"]] = violations.get(e["charter"], 0) + 1
            if e["day"] < since:
                continue
            row = card.agents.setdefault(e["agent"], AgentRow(e["agent"]))
            row.decisions += 1
            if e["verdict"] == "allow":
                row.allowed += 1
                by_rid[e["reservation"]] = (row, e["day"])
                used.setdefault(e["charter"], set()).add(e["action"])
                limit = Decimal(e["limit"]) if e.get("limit") else None
                if limit:
                    n, h = hugging.get(row.agent, (0, 0))
                    hugging[row.agent] = (n + 1, h + (Decimal(e["est_cost"]) >= limit * Decimal("0.8")))
            elif e["verdict"] == "escalate":
                row.escalated += 1
            elif e["reason"] in BOUNDARY_REASONS:
                row.boundary_denials += 1
        elif kind in ("outcome", "released") and e["reservation"] in by_rid:
            settled.add(e["reservation"])
            if kind == "outcome":
                row = by_rid[e["reservation"]][0]
                row.outcomes += 1
                row.independent_outcomes += bool(e.get("verified"))  # signed by a registered source
                actual, reserved = Decimal(e["actual"]), Decimal(e["reserved"])
                row.overruns += actual > reserved
                totals = getattr(row, "_totals", (ZERO, ZERO))
                row._totals = (totals[0] + actual, totals[1] + reserved)
        elif kind == "escalation.resolved":
            d = cp.ledger.entries[e["decision"]]
            if d["day"] >= since:
                row = card.agents.setdefault(d["agent"], AgentRow(d["agent"]))
                row.escalations_resolved += 1
                row.overrides += not e["approve"]

    for rid, (row, day) in by_rid.items():
        if rid not in settled and now - day > lease_days:
            row.unconfirmed += 1
    for row in card.agents.values():
        actual, reserved = getattr(row, "_totals", (ZERO, ZERO))
        row.estimate_ratio = (actual / reserved).quantize(Decimal("0.01")) if reserved else None
        if hasattr(row, "_totals"):
            del row._totals
        n, h = hugging.get(row.agent, (0, 0))
        row.threshold_hugging = (Decimal(h) / n).quantize(Decimal("0.01")) if n else ZERO

    for cid, rec in cp.records.items():
        m = cp.evm(cid, now)
        card.charters[cid] = CharterRow(cid, len(rec.charter.actions), len(used.get(cid, ())),
                                        violations.get(cid, 0), m["CPI"], m["SPI"])
    return card


@dataclass
class Policy:
    """Thresholds a governance board owns. Tuning them is a board decision, not an agent's."""
    min_decisions: int = 20          # a track record before any promotion
    min_independent: Decimal = Decimal("0.80")
    max_override: Decimal = Decimal("0.10")
    min_resolved: int = 3
    max_hugging: Decimal = Decimal("0.50")
    estimate_band: Decimal = Decimal("0.10")
    max_override_before_demotion: Decimal = Decimal("0.30")


class AutonomyLadder:
    """Trust as a credit limit: lowered automatically, raised only by a signed human."""

    def __init__(self, cp: ControlPlane, policy: Policy | None = None, start: int = 1):
        self.cp, self.policy, self.start = cp, policy or Policy(), start
        self.tier: dict[str, int] = {}
        self.proposals: dict[str, dict] = {}
        self.penalized: dict[str, dict] = {}   # evidence already acted on, so it is not punished twice

    def level(self, agent: str) -> int:
        return self.tier.get(agent, self.start)

    def name(self, agent: str) -> str:
        return TIERS[self.level(agent)][0]

    def authorize(self, agent, charter_id, digest, action, est_cost, now):
        """The gate, with the agent's current ceiling applied."""
        return self.cp.authorize(agent, charter_id, digest, action, est_cost, now,
                                 ceiling=TIERS[self.level(agent)][1])

    def demotion_reasons(self, row: AgentRow) -> dict[str, tuple[int, str]]:
        """Every current negative signal, keyed so the same evidence is acted on once."""
        p, reasons = self.policy, {}
        if row.boundary_denials:
            n = row.boundary_denials
            reasons["boundary"] = (n, f"probed outside its charter ({n} attempt{'s' * (n > 1)})")
        if row.overruns:
            reasons["overrun"] = (row.overruns, f"actual cost exceeded its estimate ({row.overruns}x)")
        if row.allowed >= 5 and row.threshold_hugging >= p.max_hugging:
            reasons["hugging"] = (1, f"threshold hugging {row.threshold_hugging:.0%}: a structuring pattern")
        if row.unconfirmed:
            reasons["unconfirmed"] = (row.unconfirmed, f"left actions unconfirmed ({row.unconfirmed})")
        if row.escalations_resolved >= p.min_resolved and row.override_rate >= p.max_override_before_demotion:
            reasons["override"] = (1, f"humans rejected {row.override_rate:.0%} of its escalations")
        return reasons

    def promotion_gaps(self, row: AgentRow) -> list[str]:
        p, gaps = self.policy, []
        if row.decisions < p.min_decisions:
            gaps.append(f"track record {row.decisions}/{p.min_decisions} decisions")
        if row.independent_ratio is None or row.independent_ratio < p.min_independent:
            gaps.append("outcomes not independently confirmed")
        if row.escalations_resolved < p.min_resolved or row.override_rate > p.max_override:
            gaps.append("escalations do not yet show humans agreeing")
        if row.estimate_ratio is None or abs(row.estimate_ratio - 1) > p.estimate_band:
            gaps.append("estimates not yet accurate")
        return gaps

    def review(self, card: Scorecard) -> list[tuple[str, str, str]]:
        """Demote automatically. Propose promotions; never apply them."""
        actions = []
        for agent, row in sorted(card.agents.items()):
            current = self.level(agent)
            signals = self.demotion_reasons(row)
            seen = self.penalized.setdefault(agent, {})
            fresh = [text for key, (count, text) in signals.items() if count > seen.get(key, 0)]
            if fresh:
                self.proposals.pop(agent, None)
                seen.update({key: count for key, (count, _) in signals.items()})
                new = max(0, current - len(fresh))
                if new < current:
                    self.tier[agent] = new
                    self.cp.ledger.append("autonomy.demoted", agent=agent, to=TIERS[new][0],
                                          reasons=fresh, day=card.day)
                actions.append(("DEMOTED", agent, f"{TIERS[current][0]} -> {TIERS[new][0]}: {'; '.join(fresh)}"))
            elif not signals and current < len(TIERS) - 1 and not self.promotion_gaps(row):
                proposal = {"agent": agent, "to": TIERS[current + 1][0],
                            "evidence": row.evidence_digest, "day": card.day}
                self.proposals[agent] = proposal
                self.cp.ledger.append("autonomy.proposed", **proposal)
                actions.append(("PROPOSED", agent, f"{TIERS[current][0]} -> {proposal['to']}: awaiting signed human approval"))
        return actions

    def approve(self, agent: str, human: str, signature: str, now: int) -> str:
        """A human raises the limit, bound to the evidence the proposal was made on."""
        proposal = self.proposals.get(agent)
        if proposal is None:
            raise GovernanceError(
                "no pending proposal: promotions start from evidence, not requests")
        if not self.cp.principals.verify(human, proposal, signature):
            raise GovernanceError(
                "promotions are approved only by a signing human principal")
        current = scorecard(self.cp, now).agents[agent].evidence_digest
        if current != proposal["evidence"]:
            del self.proposals[agent]
            raise GovernanceError(
                "evidence changed since the proposal: re-review before approving")
        self.tier[agent] = self.level(agent) + 1
        del self.proposals[agent]
        self.cp.ledger.append("autonomy.promoted", agent=agent, to=self.name(agent),
                              by=human, day=now)
        return self.name(agent)
