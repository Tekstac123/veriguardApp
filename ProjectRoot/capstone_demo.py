"""VeriGuard v1.0 — capstone demo: all four weeks end to end on a hold-out alert (PROVIDED, do not modify).

    python capstone_demo.py                     # rehearsal hold-out ALR-2026-9001
    python capstone_demo.py ALR-2026-9002       # the other rehearsal hold-out (confirmed sanctions match)

The live part of the M4 defense. The panel's real hold-out alerts are unseen; datapack/03_alerts/holdout_rehearsal.csv
has two rehearsal alerts whose transactions are in the data but whose alerts are not in the queue.
Writes reports/capstone_run.json.
"""
from __future__ import annotations

import sys
import traceback

from veriguard.common import LIVE, SECURITY, load_golden, load_json, make_index, write_report

CHECKS: list[dict] = []


def check(label: str, fn) -> None:
    try:
        ok, evidence = fn()
    except NotImplementedError as exc:
        ok, evidence = False, f"not implemented: {exc}"
    except Exception as exc:  # noqa: BLE001
        ok, evidence = False, f"{type(exc).__name__}: {exc}"
        traceback.print_exc(limit=1)
    CHECKS.append({"check": label, "ok": bool(ok), "evidence": str(evidence)})
    print(f"{'✔' if ok else '✘'} {label}\n    {evidence}")


def main(alert_id: str) -> None:
    from veriguard import agents, governance, ingestion, operations, reporting, retrieval, security, tools
    tokens = load_json(SECURITY / "tokens.json")
    now = tokens["_now"]
    s: dict = {}

    def w1():
        s["index"] = make_index(ingestion.build_corpus())
        tools.set_document_index(s["index"])
        r = retrieval.evaluate_qa(s["index"], load_golden())
        ok = r["recall_at_k"] >= .8 and r["citation_accuracy"] >= .9 and r["decline_rate"] >= .8 and \
            r["superseded_accuracy"] == 1.0 and r["groundedness"] >= 4.0 and r["leaks"] == 0
        return ok, (f"Recall@5 {r['recall_at_k']} · citation {r['citation_accuracy']} · decline {r['decline_rate']} · "
                    f"superseded {r['superseded_accuracy']} · grounded {r['groundedness']} · leaks {r['leaks']}")

    def w3_signin():
        for who in ("analyst", "investigator", "principal_officer", "auditor"):
            s[who] = security.principal_from_claims(tokens[who], now)
        try:
            security.principal_from_claims(tokens["forged_tenant"], now)
            return False, "forged token accepted"
        except PermissionError as exc:
            return True, f"4 staff signed in from Entra claims; forged token rejected ({exc})"

    def w1_w3_ask():
        s["audit"] = governance.AuditLog()
        r = governance.secure_ask(s["index"], "How often must PEP relationships be reviewed?", s["analyst"], s["audit"])
        ok = "12 months" in r["answer"] and r["superseded_note"] and not r["refused"]
        return ok, r["answer"].split("\n")[0][:150] + " | " + (r["superseded_note"] or "")

    def w3_security():
        red = governance.run_redteam(s["index"], audit=s["audit"])
        acc = governance.run_access_tests(s["index"], s["audit"])
        pii = governance.run_pii_tests()
        ok = red["handled_rate"] >= .95 and not red["open_critical"] and acc["unauthorized_access"] == 0 and \
            pii["pii_leaks"] == 0
        return ok, (f"red-team {red['handled']}/{red['attacks']} · access {acc['passed']}/{acc['tests']} (unauthorised "
                    f"{acc['unauthorized_access']}) · PII {pii['passed']}/20")

    def w2_w4_investigate():
        agents.reset_state()
        s["tracer"], s["budget"] = operations.Tracer(), operations.BudgetGuard(operations.CASE_BUDGET_USD)
        case = operations.run_investigation(alert_id, s["investigator"], s["index"], s["tracer"], s["budget"])
        s["case"] = case
        return case.get("status") == "Escalated to Principal Officer" and case["hitl"]["decision"] == "PENDING", \
            (f"{alert_id}: {case.get('recommendation')} · score {case['risk_score']['score']} "
             f"{case['risk_score']['band']} · typologies {[t['typology'] for t in case['typology_assessment']]} · "
             f"steps {len(case['step_log'])}")

    def w4_explain():
        e = reporting.explain_case(s["case"])
        return bool(e["factors"]) and bool(e["citations"]), " | ".join(
            f"{f['factor']} {f['points']:+d}" for f in e["factors"]) + " | " + e["threshold_note"]

    def w2_hitl():
        try:
            reporting.draft_str(alert_id, s["principal_officer"])
            return False, "STR drafted before approval"
        except ValueError:
            pass
        try:
            agents.decide(alert_id, s["investigator"], "approve", "self-approval attempt")
            return False, "Investigator approved"
        except PermissionError:
            pass
        agents.decide(alert_id, s["principal_officer"], "approve", "Evidence and policy basis reviewed; proceed to STR")
        governance.secure_tool_call(s["principal_officer"], "approve_escalation", {"alert_id": alert_id}, s["audit"])
        return s["case"]["hitl"]["decision"] == "APPROVED", "draft refused before approval; Investigator refused; PO approved"

    def w4_str():
        operations.trace_reporting(s["tracer"], s["case"], s["budget"])
        d = reporting.draft_str(alert_id, s["principal_officer"], s["case"]["trace_id"])
        return d["report_ref"].startswith("STR-DCB-2026-"), (f"{d['report_ref']} · {d['transactions_summary']['count']} "
                                                             f"transactions · due {d['filing_due_by']} · subject "
                                                             f"{d['subject']['pan_masked']}")

    def w4_trace_cost():
        spans = s["tracer"].trace(s["case"]["trace_id"])
        cost = s["tracer"].total_cost(s["case"]["trace_id"])
        names = [x["name"].split(".")[-1] for x in spans]
        ok = len({x["trace_id"] for x in spans}) == 1 and "regulatory_reporting" in names and cost <= operations.CASE_BUDGET_USD
        return ok, f"one trace: {' → '.join(names)} · ${cost:.6f} of ${operations.CASE_BUDGET_USD} cap"

    def w4_dashboard():
        d = reporting.compute_dashboard(list(agents.CASES.values()))
        row = next(r for r in d["rows"] if r["alert_id"] == alert_id)
        return bool(row["citations"]) and bool(row["evidence_txn_ids"]), \
            f"{d['cases']} case(s) · {row['band']} · HITL {row['hitl']} · {len(row['citations'])} citation(s)"

    def w3_audit():
        ok, bad = governance.verify_chain(s["audit"].entries())
        leaks = governance.pii_in_audit(s["audit"])
        return ok and leaks == 0, f"audit chain intact over {len(s['audit'].entries())} entries · raw PII in log: {leaks}"

    for label, fn in [("W1 M1 bar on the golden set", w1), ("W3 identity from Entra claims", w3_signin),
                      ("W1+W3 cited answer from the current version", w1_w3_ask),
                      ("W3 red-team, cross-role access and PII tests", w3_security),
                      ("W2+W4 hold-out alert investigated in one trace, within budget", w2_w4_investigate),
                      ("W4 explainable score", w4_explain), ("W2 human approval before any STR", w2_hitl),
                      ("W4 STR draft (schema-valid, masked)", w4_str), ("W4 one trace alert → report, cost capped",
                                                                        w4_trace_cost),
                      ("W4 dashboard links decision to evidence", w4_dashboard),
                      ("W3 tamper-evident audit trail without PII", w3_audit)]:
        check(label, fn)
    if LIVE and "tracer" in s:
        s["tracer"].export()
        if "case" in s:
            agents.persist_case(s["case"])
    passed = sum(c["ok"] for c in CHECKS)
    path = write_report({"alert_id": alert_id, "passed": passed, "total": len(CHECKS), "checks": CHECKS},
                        "capstone_run.json")
    print(f"\nCapstone: {passed}/{len(CHECKS)} checks ✔  →  {path.name}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "ALR-2026-9001")
