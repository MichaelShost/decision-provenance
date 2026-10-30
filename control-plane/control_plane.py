#!/usr/bin/env python3
"""
control_plane.py: a charter-as-code control plane for agent institutions.

Companion code for "The PMO Is Becoming a Control Plane" by Michael Shost.
Part 2 of the Agent Institutions series; extends the decision-provenance
reference implementation from "Every Agent Action Needs a Reason".

What it adds:
  1. Signed, versioned, content-addressed charters (change control as code)
  2. Delegation that can only narrow scope, budget, and time
  3. Evidence-based stage gates with separation of duties
  4. Hierarchical budget envelopes with escrow reservations (no concurrent overspend)
  5. Earned value for agent work (PV, EV, AC, CPI, SPI, EAC)
  6. A reconciliation loop that compares declared intent with observed behavior
  7. A hash-chained, tamper-evident ledger

Standard library only. HMAC stands in for asymmetric signatures to keep the
example dependency free; use Ed25519 or an HSM-backed key in production.
Time is a logical day counter so every run is deterministic.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import threading
from dataclasses import dataclass, field
from decimal import Decimal
from enum import Enum

ZERO = Decimal("0")


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()


def sha256(obj) -> str:
    return hashlib.sha256(canonical(obj)).hexdigest()


def sign(key: bytes, payload) -> str:
    return hmac.new(key, canonical(payload), hashlib.sha256).hexdigest()


class GovernanceError(Exception):
    """An invariant would be violated. The control plane fails closed."""


class Principals:
    """Humans who can sign charters and gates. Agents are deliberately absent."""

    def __init__(self):
        self._keys: dict[str, bytes] = {}

    def register(self, human_id: str, key: bytes) -> None:
        self._keys[human_id] = key

    def verify(self, human_id: str, payload, signature: str) -> bool:
        key = self._keys.get(human_id)
        return bool(key) and hmac.compare_digest(sign(key, payload), signature)


# ----------------------------------------------------------------- charters
@dataclass(frozen=True)
class Phase:
    name: str
    planned_value: Decimal          # the PV this phase earns when its gate passes
    due: int                        # logical day the gate should pass by
    exit_criteria: tuple[str, ...]  # evidence kinds required before the gate


@dataclass(frozen=True)
class Charter:
    charter_id: str
    version: int
    purpose: str
    objective: str                  # the measurable outcome the work serves
    owner: str                      # accountable human
    actions: frozenset
    budget: Decimal                 # hard ceiling (BAC plus management reserve)
    escalate_above: Decimal         # per-action human approval threshold
    phases: tuple[Phase, ...]
    expires: int                    # authority is a lease, not a possession
    parent_id: str | None = None

    def body(self) -> dict:
        return {
            "id": self.charter_id, "version": self.version, "purpose": self.purpose,
            "objective": self.objective, "owner": self.owner,
            "actions": sorted(self.actions), "budget": str(self.budget),
            "escalate_above": str(self.escalate_above), "expires": self.expires,
            "parent": self.parent_id,
            "phases": [[p.name, str(p.planned_value), p.due, list(p.exit_criteria)]
                       for p in self.phases],
        }

    @property
    def digest(self) -> str:
        return sha256(self.body())

    @property
    def bac(self) -> Decimal:
        return sum((p.planned_value for p in self.phases), ZERO)


class State(Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    CLOSED = "closed"


class Verdict(Enum):
    ALLOW = "allow"
    ESCALATE = "escalate"
    DENY = "deny"


@dataclass
class Record:
    charter: Charter
    state: State = State.ACTIVE
    phase: int = 0
    evidence: set = field(default_factory=set)
    earned: Decimal = ZERO        # EV: credited only when a gate passes
    reserved: Decimal = ZERO      # escrowed, not yet spent (includes descendants)
    committed: Decimal = ZERO     # actually spent (includes descendants)
    last_activity: int = 0


# ------------------------------------------------------------------- ledger
class Ledger:
    """Append-only and hash-chained. Edit any entry and verify() fails."""

    GENESIS = "0" * 64

    def __init__(self):
        self.entries: list[dict] = []
        self._head = self.GENESIS
        self._lock = threading.Lock()

    def append(self, kind: str, **payload) -> dict:
        with self._lock:
            entry = {"seq": len(self.entries), "kind": kind, "prev": self._head, **payload}
            entry["hash"] = sha256(entry)
            self.entries.append(entry)
            self._head = entry["hash"]
            return entry

    def verify(self) -> bool:
        prev = self.GENESIS
        for e in self.entries:
            body = {k: v for k, v in e.items() if k != "hash"}
            if e["prev"] != prev or sha256(body) != e["hash"]:
                return False
            prev = e["hash"]
        return True


# ------------------------------------------------------------ control plane
class ControlPlane:
    def __init__(self, principals: Principals, max_depth: int = 3):
        self.principals = principals
        self.ledger = Ledger()
        self.records: dict[str, Record] = {}
        self.reservations: dict[str, tuple[str, Decimal]] = {}
        self.max_depth = max_depth
        self._lock = threading.Lock()
        self._seq = 0

    # -- lineage helpers
    def _chain(self, charter_id: str) -> list[Record]:
        chain, cid = [], charter_id
        while cid:
            rec = self.records[cid]
            chain.append(rec)
            cid = rec.charter.parent_id
        return chain

    def _narrowing_errors(self, child: Charter) -> list[str]:
        parent = self.records.get(child.parent_id)
        if parent is None or parent.state is not State.ACTIVE:
            return ["parent charter is missing or not active"]
        p, errs = parent.charter, []
        if not child.actions <= p.actions:
            errs.append(f"widens actions: {sorted(child.actions - p.actions)}")
        if child.budget > p.budget:
            errs.append("budget exceeds parent")
        if child.expires > p.expires:
            errs.append("authority outlives parent")
        if len(self._chain(p.charter_id)) >= self.max_depth:
            errs.append("delegation depth cap reached")
        return errs

    # -- 1. charters as code
    def issue(self, charter: Charter, signature: str) -> None:
        if not self.principals.verify(charter.owner, charter.body(), signature):
            raise GovernanceError("charter is not signed by its accountable owner")
        if charter.bac > charter.budget:
            raise GovernanceError("phase plan exceeds budget")
        if charter.parent_id and (errs := self._narrowing_errors(charter)):
            raise GovernanceError("delegation rejected: " + "; ".join(errs))
        self.records[charter.charter_id] = Record(charter)
        self.ledger.append("charter.issued", charter=charter.charter_id,
                           version=charter.version, digest=charter.digest,
                           owner=charter.owner, parent=charter.parent_id)

    def amend(self, new: Charter, signature: str) -> list[str]:
        """Change control: a new signed version. Old digests stop working.
        Children the amendment no longer covers are suspended, not silently kept."""
        rec = self.records[new.charter_id]
        if new.version != rec.charter.version + 1 or new.owner != rec.charter.owner:
            raise GovernanceError("amendment must be the next version by the same owner")
        if not self.principals.verify(new.owner, new.body(), signature):
            raise GovernanceError("amendment is not signed by the accountable owner")
        if new.parent_id and (errs := self._narrowing_errors(new)):
            raise GovernanceError("amendment rejected: " + "; ".join(errs))
        rec.charter = new
        self.ledger.append("charter.amended", charter=new.charter_id,
                           version=new.version, digest=new.digest)
        orphaned = []
        for child in self.records.values():
            if child.charter.parent_id == new.charter_id and child.state is State.ACTIVE:
                if self._narrowing_errors(child.charter):
                    self.suspend(child.charter.charter_id, "parent amended below child scope")
                    orphaned.append(child.charter.charter_id)
        return orphaned

    def suspend(self, charter_id: str, reason: str) -> None:
        """Anyone (including the reconciler) may stop work. Only humans restart it."""
        self.records[charter_id].state = State.SUSPENDED
        self.ledger.append("charter.suspended", charter=charter_id, reason=reason)

    def resume(self, charter_id: str, human: str, signature: str) -> None:
        payload = {"resume": charter_id, "digest": self.records[charter_id].charter.digest}
        if not self.principals.verify(human, payload, signature):
            raise GovernanceError("only a human principal can resume work")
        self.records[charter_id].state = State.ACTIVE
        self.ledger.append("charter.resumed", charter=charter_id, by=human)

    # -- 2. enforcement at the moment of action
    def authorize(self, agent: str, charter_id: str, presented_digest: str,
                  action: str, est_cost: Decimal, now: int):
        rec = self.records.get(charter_id)
        if rec is None:
            verdict, reason, rid = Verdict.DENY, "no charter: orphan work", None
        elif presented_digest != rec.charter.digest:
            verdict, reason, rid = Verdict.DENY, "stale or forged charter version: rebind", None
        elif (dead := next((r for r in self._chain(charter_id)
                            if r.state is not State.ACTIVE), None)):
            verdict, reason, rid = Verdict.DENY, f"{dead.charter.charter_id} is {dead.state.value}", None
        elif now > rec.charter.expires:
            verdict, reason, rid = Verdict.DENY, "authority lease expired", None
        elif action not in rec.charter.actions:
            verdict, reason, rid = Verdict.DENY, "outside charter scope", None
        elif est_cost > rec.charter.escalate_above:
            verdict, reason, rid = Verdict.ESCALATE, "above autonomous threshold", None
        else:
            rid, blocker = self.reserve(charter_id, est_cost)
            if rid:
                verdict, reason = Verdict.ALLOW, "within purpose, scope, time, and budget"
                rec.last_activity = now
            else:
                verdict, reason = Verdict.DENY, f"envelope exhausted at {blocker}"
        self.ledger.append("decision", agent=agent, charter=charter_id, action=action,
                           est_cost=str(est_cost), verdict=verdict.value,
                           reason=reason, reservation=rid, day=now)
        return verdict, reason, rid

    # -- 3. hierarchical budget envelopes with escrow
    def reserve(self, charter_id: str, amount: Decimal):
        """Atomically escrow `amount` on the charter and every ancestor."""
        with self._lock:
            chain = self._chain(charter_id)
            for node in chain:
                if node.committed + node.reserved + amount > node.charter.budget:
                    return None, node.charter.charter_id
            for node in chain:
                node.reserved += amount
            self._seq += 1
            rid = f"R{self._seq}"
            self.reservations[rid] = (charter_id, amount)
            return rid, None

    def commit(self, rid: str, actual: Decimal) -> None:
        """Convert escrow to spend and release the remainder. An overrun is real
        money already gone: it is booked, recorded, and the charter is suspended."""
        with self._lock:
            charter_id, amount = self.reservations.pop(rid)
            for node in self._chain(charter_id):
                node.reserved -= amount
                node.committed += actual
        self.ledger.append("outcome", reservation=rid, charter=charter_id,
                           reserved=str(amount), actual=str(actual))
        if actual > amount:
            self.suspend(charter_id, f"overrun: spent {actual} against {amount}")

    def release(self, rid: str) -> None:
        with self._lock:
            charter_id, amount = self.reservations.pop(rid)
            for node in self._chain(charter_id):
                node.reserved -= amount
        self.ledger.append("released", reservation=rid, charter=charter_id)

    # -- 4. evidence-based stage gates
    def attest(self, charter_id: str, evidence: str, by: str, now: int) -> None:
        """Agents may attest evidence. Evidence informs a gate; it never passes one."""
        self.records[charter_id].evidence.add(evidence)
        self.ledger.append("evidence", charter=charter_id, evidence=evidence, by=by, day=now)

    def gate_payload(self, charter_id: str) -> dict:
        rec = self.records[charter_id]
        return {"gate": charter_id, "digest": rec.charter.digest, "phase": rec.phase}

    def pass_gate(self, charter_id: str, approver: str, signature: str, now: int) -> str:
        rec = self.records[charter_id]
        if rec.state is not State.ACTIVE:
            raise GovernanceError(f"charter is {rec.state.value}")
        if approver == rec.charter.owner:
            raise GovernanceError("separation of duties: owners do not approve their own gates")
        if not self.principals.verify(approver, self.gate_payload(charter_id), signature):
            raise GovernanceError("gate signature invalid or signer is not a human principal")
        phase = rec.charter.phases[rec.phase]
        if missing := set(phase.exit_criteria) - rec.evidence:
            raise GovernanceError(f"exit criteria unmet: {sorted(missing)}")
        rec.earned += phase.planned_value
        rec.phase += 1
        rec.evidence = set()
        rec.last_activity = now
        if rec.phase == len(rec.charter.phases):
            rec.state = State.CLOSED
        self.ledger.append("gate.passed", charter=charter_id, phase=phase.name,
                           approver=approver, earned=str(rec.earned), day=now)
        return phase.name

    # -- 5. earned value for agent work
    def evm(self, charter_id: str, now: int) -> dict:
        rec = self.records[charter_id]
        pv = sum((p.planned_value for p in rec.charter.phases if p.due <= now), ZERO)
        ev, ac, bac = rec.earned, rec.committed, rec.charter.bac
        cpi = (ev / ac) if ac else None
        spi = (ev / pv) if pv else None
        eac = (bac / cpi) if cpi else None
        return {"PV": pv, "EV": ev, "AC": ac, "BAC": bac, "CPI": cpi, "SPI": spi, "EAC": eac}

    # -- 6. reconciliation: declared intent versus observed behavior
    def reconcile(self, now: int, idle_days: int = 3, gate_grace: int = 1,
                  cpi_floor: Decimal = Decimal("0.90")) -> list[tuple[str, str, str]]:
        findings = []
        for cid, rec in self.records.items():
            c = rec.charter
            if rec.state is State.ACTIVE and now > c.expires:
                self.suspend(cid, "authority lease expired")
                findings.append(("AUTHORITY_EXPIRED", cid, f"expired day {c.expires}"))
            elif (rec.state is State.ACTIVE and rec.phase < len(c.phases)
                  and now > c.phases[rec.phase].due + gate_grace):
                self.suspend(cid, "gate debt")
                findings.append(("GATE_DEBT", cid,
                                 f"{c.phases[rec.phase].name} gate due day {c.phases[rec.phase].due}"))
            elif rec.state is State.ACTIVE and now - rec.last_activity > idle_days:
                findings.append(("ZOMBIE_CHARTER", cid, f"idle {now - rec.last_activity} days"))
            m = self.evm(cid, now)
            # Only judge cost efficiency once value was scheduled to be earned.
            if m["PV"] > 0 and m["CPI"] is not None and m["CPI"] < cpi_floor:
                eac = f"{m['EAC']:.0f}" if m["EAC"] else "unbounded"
                findings.append(("COST_TRAJECTORY", cid,
                                 f"CPI {m['CPI']:.2f}, EAC {eac} vs budget {c.budget}"))
        for rid, (cid, _) in list(self.reservations.items()):
            if any(r.state is not State.ACTIVE for r in self._chain(cid)):
                self.release(rid)
                findings.append(("ORPHAN_RESERVATION", cid, f"{rid} released"))
        for kind, cid, detail in findings:
            self.ledger.append("reconcile.finding", finding=kind, charter=cid,
                               detail=detail, day=now)
        return findings
