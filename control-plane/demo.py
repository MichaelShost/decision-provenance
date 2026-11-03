#!/usr/bin/env python3
"""Walks the control plane through the scenarios described in the article."""
import threading
from decimal import Decimal as D

from control_plane import (Charter, ControlPlane, GovernanceError, Phase,
                           Principals, sign)

KEYS = {"dana.owner": b"owner-key", "lee.pmo": b"pmo-key"}
people = Principals()
for who, key in KEYS.items():
    people.register(who, key)
cp = ControlPlane(people)


def show(label, result):
    v, why, _ = result
    print(f"  {label:<46} {v.value.upper():<9} {why}")


print("\n1. Charters are issued by accountable humans and can only narrow")
root = Charter(
    "CH-100", 1, "Modernize supplier onboarding",
    "Cut supplier onboarding cycle time from 21 to 7 days",
    "dana.owner",
    frozenset({"read.repo", "write.repo", "run.tests", "draft.doc", "send.email"}),
    budget=D("1000"), escalate_above=D("100"), expires=30,
    phases=(Phase("Discover", D("250"), 5, ("requirements.accepted",)),
            Phase("Build", D("500"), 15, ("tests.passed", "security.reviewed")),
            Phase("Transition", D("200"), 20, ("runbook.published",))))
cp.issue(root, sign(KEYS["dana.owner"], root.body()))
print(f"  CH-100 issued   digest {root.digest[:12]}   BAC {root.bac}   reserve {root.budget - root.bac}")

build = Charter(
    "CH-110", 1, "Build onboarding workflow service", "Workflow service passes acceptance suite",
    "dana.owner", frozenset({"read.repo", "write.repo", "run.tests"}),
    budget=D("400"), escalate_above=D("50"), expires=18,
    phases=(Phase("Build", D("400"), 15, ("tests.passed",)),), parent_id="CH-100")
cp.issue(build, sign(KEYS["dana.owner"], build.body()))
print(f"  CH-110 delegated, narrower than CH-100   digest {build.digest[:12]}")

wide = Charter("CH-111", 1, "Clean up", "n/a", "dana.owner",
               frozenset({"write.repo", "delete.prod"}), D("500"), D("50"), (), 40, "CH-110")
try:
    cp.issue(wide, sign(KEYS["dana.owner"], wide.body()))
except GovernanceError as e:
    print(f"  CH-111 rejected at delegation: {e}")

forged = Charter("CH-112", 1, "Self-chartered work", "n/a", "dana.owner",
                 frozenset({"read.repo"}), D("10"), D("5"), (), 10, "CH-110")
try:
    cp.issue(forged, sign(b"agent-guessed-key", forged.body()))
except GovernanceError as e:
    print(f"  CH-112 (agent self-charter) rejected: {e}")

print("\n2. Enforcement at the moment of action")
r = cp.authorize("agent.builder", "CH-110", build.digest, "write.repo", D("20"), now=3)
show("write.repo, $20, inside charter", r)
cp.commit(r[2], D("18"))
show("send.email (parent allows, child does not)",
     cp.authorize("agent.builder", "CH-110", build.digest, "send.email", D("1"), now=3))
show("run.tests, $75 (above $50 threshold)",
     cp.authorize("agent.builder", "CH-110", build.digest, "run.tests", D("75"), now=3))
show("orphan work, no charter",
     cp.authorize("agent.rogue", "CH-999", "0" * 64, "read.repo", D("1"), now=3))

print("\n3. Change control: amendment invalidates the old version")
build_v2 = Charter(**{**build.__dict__, "version": 2, "expires": 16})
cp.amend(build_v2, sign(KEYS["dana.owner"], build_v2.body()))
show("agent still bound to v1 digest",
     cp.authorize("agent.builder", "CH-110", build.digest, "read.repo", D("2"), now=4))
show("agent rebinds to v2 digest",
     cp.authorize("agent.builder", "CH-110", build_v2.digest, "read.repo", D("2"), now=4))

print("\n4. Stage gates: evidence informs, humans decide, owners do not self-approve")
cp.attest("CH-100", "requirements.draft", by="agent.analyst", now=4)
for who, key in [("agent.analyst", b"agent-guessed-key"),
                 ("dana.owner", KEYS["dana.owner"]),
                 ("lee.pmo", KEYS["lee.pmo"])]:
    try:
        cp.pass_gate("CH-100", who, sign(key, cp.gate_payload("CH-100")), now=4)
    except GovernanceError as e:
        print(f"  gate attempt by {who:<14} refused: {e}")
cp.attest("CH-100", "requirements.accepted", by="agent.analyst", now=5)
passed = cp.pass_gate("CH-100", "lee.pmo", sign(KEYS["lee.pmo"], cp.gate_payload("CH-100")), now=5)
print(f"  gate attempt by lee.pmo        passed: {passed} (EV credited 250)")

print("\n5. Concurrency: 40 agents race for one envelope")
before = cp.records["CH-110"]
headroom = before.charter.budget - before.committed - before.reserved
barrier, granted = threading.Barrier(40), []


def worker(i):
    v, _, rid = cp.authorize(f"agent.w{i}", "CH-110", build_v2.digest, "run.tests", D("30"), now=6)
    barrier.wait()
    if rid:
        cp.commit(rid, D("30"))
        granted.append(i)


threads = [threading.Thread(target=worker, args=(i,)) for i in range(40)]
for t in threads:
    t.start()
for t in threads:
    t.join()
after = cp.records["CH-110"]
print(f"  headroom {headroom}; requested {40 * 30}; granted {len(granted)} x 30 = "
      f"{len(granted) * 30}; CH-110 spent {after.committed} of {after.charter.budget}")

print("\n6. Suspending a parent stops every descendant at its next action")
cp.suspend("CH-100", "steering committee pause")
show("child acts while parent suspended",
     cp.authorize("agent.builder", "CH-110", build_v2.digest, "read.repo", D("1"), now=7))
cp.resume("CH-100", "dana.owner",
          sign(KEYS["dana.owner"], {"resume": "CH-100", "digest": root.digest}))
print("  CH-100 resumed by its accountable owner (a signed human act)")

print("\n7. Reconciliation on day 17 (no Build gate yet)")
for m in ("CH-100", "CH-110"):
    e = cp.evm(m, now=17)
    fmt = lambda x: "n/a" if x is None else f"{x:.2f}"
    print(f"  {m}: PV {e['PV']} EV {e['EV']} AC {e['AC']} CPI {fmt(e['CPI'])} SPI {fmt(e['SPI'])}")
for kind, cid, detail in cp.reconcile(now=17):
    print(f"  finding {kind:<18} {cid}  {detail}")

print("\n8. Tamper evidence")
print(f"  ledger entries {len(cp.ledger.entries)}, chain verifies: {cp.ledger.verify()}")
cp.ledger.entries[5]["reason"] = "rewritten after the fact"
print(f"  after editing one historical entry, chain verifies: {cp.ledger.verify()}")

print("\n9. Timeouts don't release money. Evidence does. (v1.1)")
records = {}  # stand-in for the tool's system of record, keyed by idempotency key
cp2 = ControlPlane(people, in_doubt_cap=D("25"), system_of_record=lambda rid: records.get(rid))
ops = Charter("CH-200", 1, "Vendor data refresh", "Refresh supplier records nightly", "dana.owner",
              frozenset({"call.api"}), budget=D("100"), escalate_above=D("50"), expires=30, phases=())
cp2.issue(ops, sign(KEYS["dana.owner"], ops.body()))
_, _, rid = cp2.authorize("agent.sync", "CH-200", ops.digest, "call.api", D("25"), now=1)
print(f"  agent.sync reserves $25 as {rid}, then times out and never confirms")
for kind, cid, detail in cp2.reconcile(now=3):
    print(f"  day 3  {kind:<20} {detail}")
print(f"  CH-200 still encumbered: ${cp2.records['CH-200'].reserved} held as spent, nothing released")
show("agent.sync tries new spend while in doubt",
     cp2.authorize("agent.sync", "CH-200", ops.digest, "call.api", D("5"), now=3))
records[rid] = D("22")  # the provider's ledger shows the call did happen
for kind, cid, detail in cp2.reconcile(now=4):
    print(f"  day 4  {kind:<20} {detail}")
cp2.commit(rid, D("22"))  # the agent's late retry arrives
print(f"  late retry from agent.sync: booked once, spent {cp2.records['CH-200'].committed} "
      f"(ledger: {cp2.ledger.entries[-1]['kind']})")
