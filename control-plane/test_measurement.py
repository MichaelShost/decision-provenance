#!/usr/bin/env python3
"""Tests for measurement.py. Run: python3 -m unittest -v"""
import unittest
from decimal import Decimal as D

from control_plane import (Charter, ControlPlane, GovernanceError, Phase, Principals, Verdict,
                           confirmation_payload, sign)
from measurement import AutonomyLadder, Policy, resolve_escalation, scorecard

KEYS = {"owner": b"k-owner", "pmo": b"k-pmo"}
PAY = b"k-payments"


def setup(policy=None):
    p = Principals()
    for who, k in KEYS.items():
        p.register(who, k)
    cp = ControlPlane(p)
    ch = Charter("C", 1, "p", "o", "owner", frozenset({"a", "b", "c"}), D("5000"), D("50"),
                 (Phase("P", D("100"), 50, ("e",)),), 90)
    cp.issue(ch, sign(KEYS["owner"], ch.body()))
    cp.register_source("payments", PAY, "owner", sign(KEYS["owner"], {"register_source": "payments"}))
    return cp, ch, AutonomyLadder(cp, policy)


def act(cp, ladder, ch, agent, est, day, action="a", actual=None, source="agent"):
    v, why, rid = ladder.authorize(agent, "C", ch.digest, action, D(str(est)), day)
    if rid:
        amount = D(str(actual if actual is not None else est))
        sig = sign(PAY, confirmation_payload(rid, amount)) if source == "payments" else None
        cp.commit(rid, amount, source=source, signature=sig)
    return v, why, rid


def good_record(cp, ladder, ch, agent="good", n=24, escalations=4):
    for i in range(n):
        act(cp, ladder, ch, agent, 5, 1 + i % 10, actual=D("4.9"), source="payments")
    for d in range(escalations):
        v, _, _ = act(cp, ladder, ch, agent, 30, 2 + d)
        seq = cp.ledger.entries[-1]["seq"]
        resolve_escalation(cp, seq, "pmo", sign(KEYS["pmo"], {"escalation": seq, "approve": True}), True)


class TestScorecard(unittest.TestCase):
    def test_refuses_tampered_ledger(self):
        cp, ch, ladder = setup()
        act(cp, ladder, ch, "x", 5, 1)
        cp.ledger.entries[1]["est_cost"] = "0"
        with self.assertRaisesRegex(GovernanceError, "tampered evidence"):
            scorecard(cp, now=2)

    def test_self_reported_outcomes_are_not_independent(self):
        cp, ch, ladder = setup()
        act(cp, ladder, ch, "x", 5, 1)  # agent confirms its own outcome
        act(cp, ladder, ch, "x", 5, 1, source="payments")
        self.assertEqual(scorecard(cp, now=2).agents["x"].independent_ratio, D("0.5"))

    def test_threshold_hugging_detects_structuring(self):
        cp, ch, ladder = setup()
        for i in range(6):
            act(cp, ladder, ch, "s", "9.9", 1 + i)  # ASSISTED ceiling is $10
        self.assertEqual(scorecard(cp, now=7).agents["s"].threshold_hugging, D("1.00"))

    def test_authority_utilization_and_window(self):
        cp, ch, ladder = setup()
        act(cp, ladder, ch, "x", 5, 1, action="a")
        act(cp, ladder, ch, "x", 5, 40, action="b")
        card = scorecard(cp, now=45, window=30)
        self.assertEqual(card.charters["C"].authority_used, 1)  # day-1 activity is outside the window
        self.assertEqual(card.agents["x"].decisions, 1)

    def test_override_rate_from_signed_resolutions(self):
        cp, ch, ladder = setup()
        act(cp, ladder, ch, "x", 30, 1)
        seq = cp.ledger.entries[-1]["seq"]
        with self.assertRaises(GovernanceError):
            resolve_escalation(cp, seq, "x", sign(b"guess", {"escalation": seq, "approve": True}), True)
        resolve_escalation(cp, seq, "pmo", sign(KEYS["pmo"], {"escalation": seq, "approve": False}), False)
        self.assertEqual(scorecard(cp, now=2).agents["x"].override_rate, D("1"))

    def test_claimed_independence_without_signature_never_counts(self):
        cp, ch, ladder = setup()
        _, _, rid = ladder.authorize("x", "C", ch.digest, "a", D("5"), 1)
        with self.assertRaises(GovernanceError):
            cp.commit(rid, D("5"), source="payments")  # a label, no signature
        self.assertEqual(scorecard(cp, now=2).agents["x"].independent_outcomes, 0)

    def test_stop_integrity_is_zero_by_construction(self):
        cp, ch, ladder = setup()
        cp.suspend("C", "pause")
        act(cp, ladder, ch, "x", 5, 1)
        self.assertEqual(scorecard(cp, now=2).charters["C"].stop_violations, 0)


class TestLadder(unittest.TestCase):
    def test_tier_ceiling_enforced_at_gate(self):
        cp, ch, ladder = setup()
        self.assertEqual(act(cp, ladder, ch, "x", 9, 1)[0], Verdict.ALLOW)
        self.assertEqual(act(cp, ladder, ch, "x", 11, 1)[1], "above agent autonomy tier")

    def test_demotion_is_automatic(self):
        cp, ch, ladder = setup()
        act(cp, ladder, ch, "p", 1, 1, action="z")  # outside the charter
        ladder.review(scorecard(cp, now=2))
        self.assertEqual(ladder.name("p"), "SUPERVISED")
        self.assertEqual(act(cp, ladder, ch, "p", 1, 2)[0], Verdict.ESCALATE)

    def test_same_evidence_is_not_punished_twice(self):
        cp, ch, ladder = setup()
        ladder.tier["p"] = 2
        act(cp, ladder, ch, "p", 1, 1, action="z")
        ladder.review(scorecard(cp, now=2))
        ladder.review(scorecard(cp, now=3))
        self.assertEqual(ladder.name("p"), "ASSISTED")

    def test_promotion_is_proposed_never_applied(self):
        cp, ch, ladder = setup()
        good_record(cp, ladder, ch)
        actions = ladder.review(scorecard(cp, now=11))
        self.assertEqual(actions[0][0], "PROPOSED")
        self.assertEqual(ladder.name("good"), "ASSISTED")

    def test_short_track_record_is_not_promoted(self):
        cp, ch, ladder = setup()
        good_record(cp, ladder, ch, n=10)
        self.assertEqual(ladder.review(scorecard(cp, now=11)), [])

    def test_only_humans_approve_promotions(self):
        cp, ch, ladder = setup()
        good_record(cp, ladder, ch)
        ladder.review(scorecard(cp, now=11))
        with self.assertRaisesRegex(GovernanceError, "signing human"):
            ladder.approve("good", "good", sign(b"guess", ladder.proposals["good"]), now=11)

    def test_approval_fails_if_evidence_changed(self):
        cp, ch, ladder = setup()
        good_record(cp, ladder, ch)
        ladder.review(scorecard(cp, now=11))
        proposal = dict(ladder.proposals["good"])
        act(cp, ladder, ch, "good", 5, 11, actual=5, source="payments")
        with self.assertRaisesRegex(GovernanceError, "evidence changed"):
            ladder.approve("good", "pmo", sign(KEYS["pmo"], proposal), now=11)
        self.assertEqual(ladder.name("good"), "ASSISTED")

    def test_signed_approval_on_current_evidence_promotes_one_tier(self):
        cp, ch, ladder = setup()
        good_record(cp, ladder, ch)
        ladder.review(scorecard(cp, now=11))
        self.assertEqual(ladder.approve("good", "pmo", sign(KEYS["pmo"], ladder.proposals["good"]), now=11),
                         "TRUSTED")
        self.assertEqual(act(cp, ladder, ch, "good", 30, 11)[0], Verdict.ALLOW)

    def test_self_reported_success_never_earns_promotion(self):
        cp, ch, ladder = setup()
        for i in range(24):
            act(cp, ladder, ch, "s", 5, 1 + i % 10)  # every outcome self-reported
        self.assertEqual(ladder.review(scorecard(cp, now=11)), [])


if __name__ == "__main__":
    unittest.main()
