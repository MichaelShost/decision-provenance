#!/usr/bin/env python3
"""Tests for control_plane.py. Run: python3 -m unittest -v"""
import threading
import unittest
from decimal import Decimal as D

from control_plane import (Charter, ControlPlane, GovernanceError, Phase,
                           Principals, State, Verdict, sign)

OWNER, PMO = "owner", "pmo"
KEYS = {OWNER: b"k-owner", PMO: b"k-pmo"}


def plane():
    p = Principals()
    for who, k in KEYS.items():
        p.register(who, k)
    cp = ControlPlane(p)
    root = Charter("ROOT", 1, "p", "o", OWNER, frozenset({"a", "b", "c"}), D("1000"),
                   D("100"), (Phase("P1", D("400"), 5, ("e1",)),
                              Phase("P2", D("500"), 10, ("e2",))), 20)
    cp.issue(root, sign(KEYS[OWNER], root.body()))
    child = Charter("KID", 1, "p", "o", OWNER, frozenset({"a", "b"}), D("300"),
                    D("50"), (Phase("K1", D("300"), 8, ("k1",)),), 15, "ROOT")
    cp.issue(child, sign(KEYS[OWNER], child.body()))
    return cp, root, child


class NaiveBudget:
    """Check-then-spend: the pattern most agent frameworks start with."""

    def __init__(self, limit):
        self.limit, self.spent, self._lock = limit, D("0"), threading.Lock()

    def try_spend(self, amount, barrier):
        ok = self.spent + amount <= self.limit   # time of check
        barrier.wait()                           # every agent checks before anyone spends
        if ok:
            with self._lock:
                self.spent += amount             # time of use
        return ok


def race(n, fn):
    barrier = threading.Barrier(n)
    threads = [threading.Thread(target=fn, args=(barrier,)) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


class TestCharters(unittest.TestCase):
    def test_delegation_cannot_widen(self):
        cp, _, _ = plane()
        bad = Charter("BAD", 1, "p", "o", OWNER, frozenset({"a", "z"}), D("10"), D("5"),
                      (), 10, "KID")
        with self.assertRaisesRegex(GovernanceError, "widens actions"):
            cp.issue(bad, sign(KEYS[OWNER], bad.body()))

    def test_agents_cannot_charter_themselves(self):
        cp, _, _ = plane()
        c = Charter("SELF", 1, "p", "o", OWNER, frozenset({"a"}), D("1"), D("1"), (), 5, "KID")
        with self.assertRaisesRegex(GovernanceError, "not signed"):
            cp.issue(c, sign(b"guessed", c.body()))

    def test_amendment_invalidates_old_digest(self):
        cp, _, child = plane()
        v2 = Charter(**{**child.__dict__, "version": 2, "expires": 12})
        cp.amend(v2, sign(KEYS[OWNER], v2.body()))
        v, why, _ = cp.authorize("ag", "KID", child.digest, "a", D("1"), now=1)
        self.assertEqual((v, why), (Verdict.DENY, "stale or forged charter version: rebind"))
        self.assertEqual(cp.authorize("ag", "KID", v2.digest, "a", D("1"), now=1)[0], Verdict.ALLOW)

    def test_narrowing_parent_suspends_uncovered_children(self):
        cp, root, _ = plane()
        v2 = Charter(**{**root.__dict__, "version": 2, "actions": frozenset({"a"})})
        self.assertEqual(cp.amend(v2, sign(KEYS[OWNER], v2.body())), ["KID"])
        self.assertIs(cp.records["KID"].state, State.SUSPENDED)


class TestEnforcement(unittest.TestCase):
    def test_verdicts(self):
        cp, _, child = plane()
        d = child.digest
        self.assertEqual(cp.authorize("ag", "KID", d, "a", D("10"), 1)[0], Verdict.ALLOW)
        self.assertEqual(cp.authorize("ag", "KID", d, "c", D("1"), 1)[0], Verdict.DENY)
        self.assertEqual(cp.authorize("ag", "KID", d, "a", D("60"), 1)[0], Verdict.ESCALATE)
        self.assertEqual(cp.authorize("ag", "KID", d, "a", D("1"), 16)[1], "authority lease expired")
        self.assertEqual(cp.authorize("ag", "NONE", d, "a", D("1"), 1)[1], "no charter: orphan work")

    def test_suspended_ancestor_stops_descendants(self):
        cp, _, child = plane()
        cp.suspend("ROOT", "pause")
        self.assertEqual(cp.authorize("ag", "KID", child.digest, "a", D("1"), 1)[1], "ROOT is suspended")

    def test_only_humans_resume(self):
        cp, root, _ = plane()
        cp.suspend("ROOT", "pause")
        with self.assertRaises(GovernanceError):
            cp.resume("ROOT", "agent", sign(b"guessed", {"resume": "ROOT", "digest": root.digest}))


class TestBudgets(unittest.TestCase):
    def test_naive_check_then_spend_overspends(self):
        naive = NaiveBudget(D("300"))
        race(40, lambda b: naive.try_spend(D("30"), b))
        self.assertEqual(naive.spent, D("1200"))  # 4x the limit

    def test_escrow_never_overspends_under_contention(self):
        cp, _, child = plane()
        rids = []

        def agent(barrier):
            _, _, rid = cp.authorize("ag", "KID", child.digest, "a", D("30"), 1)
            barrier.wait()
            if rid:
                cp.commit(rid, D("30"))
                rids.append(rid)

        race(40, agent)
        self.assertEqual(len(rids), 10)
        self.assertEqual(cp.records["KID"].committed, D("300"))
        self.assertEqual(cp.records["ROOT"].committed, D("300"))  # rolls up

    def test_overrun_is_booked_and_suspends(self):
        cp, _, child = plane()
        _, _, rid = cp.authorize("ag", "KID", child.digest, "a", D("20"), 1)
        cp.commit(rid, D("35"))
        self.assertEqual(cp.records["KID"].committed, D("35"))
        self.assertIs(cp.records["KID"].state, State.SUSPENDED)


class TestGates(unittest.TestCase):
    def test_gate_rules(self):
        cp, _, _ = plane()
        pay = cp.gate_payload("ROOT")
        with self.assertRaisesRegex(GovernanceError, "separation of duties"):
            cp.pass_gate("ROOT", OWNER, sign(KEYS[OWNER], pay), 2)
        with self.assertRaisesRegex(GovernanceError, "not a human"):
            cp.pass_gate("ROOT", "agent", sign(b"guessed", pay), 2)
        with self.assertRaisesRegex(GovernanceError, "exit criteria unmet"):
            cp.pass_gate("ROOT", PMO, sign(KEYS[PMO], pay), 2)
        cp.attest("ROOT", "e1", "agent", 2)
        self.assertEqual(cp.pass_gate("ROOT", PMO, sign(KEYS[PMO], pay), 2), "P1")
        self.assertEqual(cp.records["ROOT"].earned, D("400"))


class TestEvmAndReconcile(unittest.TestCase):
    def test_evm(self):
        cp, _, child = plane()
        _, _, rid = cp.authorize("ag", "KID", child.digest, "a", D("40"), 1)
        cp.commit(rid, D("40"))
        cp.attest("ROOT", "e1", "agent", 4)
        cp.pass_gate("ROOT", PMO, sign(KEYS[PMO], cp.gate_payload("ROOT")), 4)
        m = cp.evm("ROOT", now=6)
        self.assertEqual((m["PV"], m["EV"], m["AC"]), (D("400"), D("400"), D("40")))
        self.assertEqual(m["CPI"], D("10"))

    def test_reconcile_finds_gate_debt_and_releases_confirmed_orphans(self):
        cp, _, child = plane()
        cp.system_of_record = lambda rid: D("0")  # system of record confirms nothing was spent
        cp.authorize("ag", "KID", child.digest, "a", D("10"), 1)  # reserved, never completed
        kinds = {k for k, _, _ in cp.reconcile(now=9)}
        self.assertIn("GATE_DEBT", kinds)
        self.assertIn("ORPHAN_RESERVATION", kinds)
        self.assertEqual(cp.records["ROOT"].reserved, D("0"))


class TestInDoubt(unittest.TestCase):
    """Timeouts don't release money. Evidence does."""

    def timed_out(self, amount="40"):
        cp, _, child = plane()
        _, _, rid = cp.authorize("ag", "KID", child.digest, "a", D(amount), 1)
        return cp, child, rid  # the agent never confirms

    def test_timeout_never_frees_budget(self):
        cp, _, rid = self.timed_out()
        findings = cp.reconcile(now=3)  # lease expired, no evidence available
        self.assertIn(("IN_DOUBT", "KID", f"{rid} unconfirmed: held as spent"), findings)
        self.assertEqual(cp.records["KID"].reserved, D("40"))
        self.assertEqual(cp.records["ROOT"].reserved, D("40"))

    def test_stopped_charter_does_not_release_without_evidence(self):
        cp, _, rid = self.timed_out()
        cp.suspend("KID", "pause")
        cp.reconcile(now=1)
        self.assertIn(rid, cp.in_doubt)
        self.assertEqual(cp.records["KID"].reserved, D("40"))

    def test_unresolved_escalates_to_owner(self):
        cp, _, rid = self.timed_out()
        cp.reconcile(now=3)
        kinds = {k for k, _, _ in cp.reconcile(now=5)}
        self.assertIn("IN_DOUBT_ESCALATED", kinds)

    def test_system_of_record_commits_actual_cost(self):
        cp, _, rid = self.timed_out()
        cp.reconcile(now=3)
        cp.system_of_record = lambda r: D("37")
        kinds = {k for k, _, _ in cp.reconcile(now=4)}
        self.assertIn("IN_DOUBT_RESOLVED", kinds)
        self.assertEqual((cp.records["KID"].committed, cp.records["KID"].reserved), (D("37"), D("0")))

    def test_late_retry_is_never_booked_twice(self):
        cp, _, rid = self.timed_out()
        cp.system_of_record = lambda r: D("37")
        cp.reconcile(now=3)
        cp.commit(rid, D("37"))  # the agent finally confirms, after resolution
        self.assertEqual(cp.records["ROOT"].committed, D("37"))
        self.assertEqual(cp.ledger.entries[-1]["kind"], "outcome.duplicate")

    def test_in_doubt_exposure_is_capped_per_agent(self):
        cp, child, rid = self.timed_out("40")
        cp.in_doubt_cap = D("40")
        cp.reconcile(now=3)
        v, why, _ = cp.authorize("ag", "KID", child.digest, "a", D("1"), 3)
        self.assertEqual((v, why), (Verdict.DENY, "in-doubt exposure cap reached: resolve before new spend"))
        self.assertEqual(cp.authorize("other", "ROOT", cp.records["ROOT"].charter.digest, "a", D("1"), 3)[0],
                         Verdict.ALLOW)


class TestLedger(unittest.TestCase):
    def test_tamper_evident(self):
        cp, _, child = plane()
        cp.authorize("ag", "KID", child.digest, "a", D("1"), 1)
        self.assertTrue(cp.ledger.verify())
        cp.ledger.entries[1]["owner"] = "someone-else"
        self.assertFalse(cp.ledger.verify())


if __name__ == "__main__":
    unittest.main()
