"""Decision provenance gate: a minimal reference sketch.

Every agent action must carry a decision record that binds purpose,
identity, authority, and budget BEFORE the action executes.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum


class Verdict(str, Enum):
    ALLOW = "allow"
    ESCALATE = "escalate"      # pause and route to the accountable human
    DENY = "deny"              # refuse this action, agent continues
    TERMINATE = "terminate"    # revoke the agent's credentials and stop it


@dataclass(frozen=True)
class Charter:
    """Purpose issued by an accountable human. Agents inherit, never widen."""
    charter_id: str
    owner: str                      # accountable human
    purpose: str
    allowed_actions: frozenset[str]
    budget_usd: float
    escalate_above_usd: float
    parent_id: str | None = None

    def delegate(self, purpose: str, actions: set[str], budget_usd: float) -> "Charter":
        """Create a child charter. Scope and budget can only narrow."""
        if not actions <= self.allowed_actions:
            raise PermissionError(f"cannot widen scope: {actions - self.allowed_actions}")
        if budget_usd > self.budget_usd:
            raise PermissionError("cannot widen budget")
        return Charter(
            charter_id=f"{self.charter_id}/{uuid.uuid4().hex[:6]}",
            owner=self.owner,
            purpose=purpose,
            allowed_actions=frozenset(actions),
            budget_usd=budget_usd,
            escalate_above_usd=min(self.escalate_above_usd, budget_usd),
            parent_id=self.charter_id,
        )


@dataclass
class DecisionRecord:
    """Created BEFORE the action. The 'why' exists before the 'what'."""
    agent_id: str
    agent_key_fingerprint: str
    charter_id: str
    action: str
    target: str
    estimated_cost_usd: float
    rationale: str                  # model-stated reason: evidence, not authority
    inputs: list[str]
    alternatives_considered: list[str]
    confidence: float
    record_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created_at: float = field(default_factory=time.time)
    verdict: str | None = None
    verdict_reasons: list[str] = field(default_factory=list)


class Ledger:
    """Append-only, hash-chained log. Tampering breaks the chain."""

    def __init__(self) -> None:
        self.entries: list[dict] = []
        self.head = "genesis"

    def append(self, kind: str, payload: dict) -> str:
        body = json.dumps({"kind": kind, "prev": self.head, "payload": payload},
                          sort_keys=True, default=str)
        digest = hashlib.sha256(body.encode()).hexdigest()
        self.entries.append({"hash": digest, "body": body})
        self.head = digest
        return digest

    def verify(self) -> bool:
        prev = "genesis"
        for entry in self.entries:
            body = json.loads(entry["body"])
            if body["prev"] != prev:
                return False
            if hashlib.sha256(entry["body"].encode()).hexdigest() != entry["hash"]:
                return False
            prev = entry["hash"]
        return True


class DecisionGate:
    """Policy enforcement point in the control plane. Fails closed."""

    def __init__(self, registry: dict[str, str], charters: dict[str, Charter], ledger: Ledger):
        self.registry = registry    # agent_id -> registered key fingerprint
        self.charters = charters
        self.ledger = ledger
        self.spent: dict[str, float] = {}
        self.revoked: set[str] = set()

    def evaluate(self, rec: DecisionRecord) -> Verdict:
        reasons: list[str] = []
        charter = self.charters.get(rec.charter_id)

        # 1. Identity: a registered agent with the registered key, not revoked.
        if rec.agent_id in self.revoked:
            return self._decide(rec, Verdict.DENY, ["agent revoked"])
        if self.registry.get(rec.agent_id) != rec.agent_key_fingerprint:
            return self._decide(rec, Verdict.TERMINATE, ["identity mismatch"])

        # 2. Purpose: the action must trace to a live charter.
        if charter is None:
            return self._decide(rec, Verdict.DENY, ["no charter: action has no purpose"])
        if not rec.rationale.strip():
            return self._decide(rec, Verdict.DENY, ["no stated rationale"])

        # 3. Authority: the action must be inside the charter's scope.
        if rec.action not in charter.allowed_actions:
            return self._decide(rec, Verdict.DENY, [f"'{rec.action}' outside charter scope"])

        # 4. Budget: hard ceiling, human threshold below it.
        spent = self.spent.get(charter.charter_id, 0.0)
        if spent + rec.estimated_cost_usd > charter.budget_usd:
            return self._decide(rec, Verdict.ESCALATE, ["would exceed charter budget"])
        if rec.estimated_cost_usd > charter.escalate_above_usd:
            reasons.append("above human approval threshold")

        # 5. Confidence: low-confidence decisions go to a human.
        if rec.confidence < 0.6:
            reasons.append(f"low confidence ({rec.confidence:.2f})")

        if reasons:
            return self._decide(rec, Verdict.ESCALATE, reasons)
        self.spent[charter.charter_id] = spent + rec.estimated_cost_usd
        return self._decide(rec, Verdict.ALLOW, ["within purpose, authority, and budget"])

    def _decide(self, rec: DecisionRecord, verdict: Verdict, reasons: list[str]) -> Verdict:
        rec.verdict, rec.verdict_reasons = verdict.value, reasons
        if verdict is Verdict.TERMINATE:
            self.revoked.add(rec.agent_id)
        self.ledger.append("decision", asdict(rec))   # recorded BEFORE any action runs
        return verdict


def act(gate: DecisionGate, rec: DecisionRecord, tool) -> str:
    """The only path to a tool. No record, no action."""
    verdict = gate.evaluate(rec)
    if verdict is not Verdict.ALLOW:
        return f"{verdict.value.upper()}: {', '.join(rec.verdict_reasons)}"
    result = tool(rec.target)
    gate.ledger.append("outcome", {"record_id": rec.record_id, "result": result})
    return f"ALLOW: {result}"


if __name__ == "__main__":
    ledger = Ledger()
    root = Charter("Q4-portfolio-review", owner="Head of Delivery",
                   purpose="Prepare the Q4 portfolio health review",
                   allowed_actions=frozenset({"read_status", "draft_report", "send_email"}),
                   budget_usd=50.0, escalate_above_usd=20.0)
    child = root.delegate("Summarize program status", {"read_status", "draft_report"}, 10.0)

    gate = DecisionGate(registry={"agent-7": "fp:ab12"},
                        charters={root.charter_id: root, child.charter_id: child},
                        ledger=ledger)

    def record(action, cost=1.0, key="fp:ab12", charter=child.charter_id, conf=0.9, why="needed for review"):
        return DecisionRecord("agent-7", key, charter, action, "program-42", cost, why,
                              ["status-feed"], ["skip program"], conf)

    print(act(gate, record("read_status"), lambda t: f"status of {t}"))
    print(act(gate, record("send_email"), lambda t: "sent"))
    print(act(gate, record("draft_report", cost=12.0), lambda t: "drafted"))
    print(act(gate, record("read_status", key="fp:ab1Z"), lambda t: "read"))
    print(act(gate, record("read_status"), lambda t: "read"))
    try:
        child.delegate("Wider scope", {"read_status", "delete_records"}, 5.0)
    except PermissionError as e:
        print(f"DELEGATION BLOCKED: {e}")
    print("ledger intact:", ledger.verify(), "| entries:", len(ledger.entries))
