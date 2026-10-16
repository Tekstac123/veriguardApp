"""Week 4 self-check — run it after every TODO you finish (PROVIDED, do not modify).

    python check_week4.py              # every task
    python check_week4.py --task 0     # Azure values in .env · 1 → reporting.py · 2 → operations.py
"""
from __future__ import annotations

import os
import sys

os.environ["VERIGUARD_MODE"] = "offline"
os.environ.setdefault("VERIGUARD_LLM", "extractive")
from veriguard.common import dev_principal, load_labels, make_index  # noqa: E402
from veriguard.selfcheck import azure_env_check, check, summary  # noqa: E402

st: dict = {}


def ctx() -> dict:
    if not st:
        from veriguard import agents, tools
        from veriguard.ingestion import build_corpus
        index = make_index(build_corpus())
        tools.set_document_index(index)
        agents.reset_state()
        st.update(index=index, inv=dev_principal("Investigator", "EMP-IN-01"), po=dev_principal("PrincipalOfficer", "EMP-PO-01"))
    return st


def task0() -> None:
    print("\nTask 0 · your Azure values in .env (Weeks 1–4)")
    check("T0", "every Week 1–4 Azure value is filled in .env, spelled exactly as in the guides", lambda: azure_env_check(4))


def task1() -> None:
    print("\nTask 1 · veriguard/reporting.py")
    from veriguard import agents, operations as O, reporting as R

    def explain():
        s = ctx()
        case = agents.investigate("ALR-2026-0417", s["inv"], s["index"])
        agents.persist_case(case)
        e = R.explain_case(case)
        assert e["score"] == 80 and e["band"] == "High", f"explain_case score/band {e['score']}/{e['band']}, expected 80/High"
        assert {"factors", "typologies", "citations", "approval_trail", "threshold_note"} <= set(e), f"keys {sorted(e)}"
        assert "70" in e["threshold_note"] and "Principal Officer" in e["threshold_note"], f"threshold_note {e['threshold_note']!r}"
        low = R.explain_case(agents.investigate("ALR-2026-0452", s["inv"], s["index"]))
        assert "approval" not in low["threshold_note"].lower() or "below" in low["threshold_note"].lower(), \
            f"a Low band score must not demand approval: {low['threshold_note']!r}"
        return True

    def str_rules():
        s = ctx()
        try:
            R.draft_str("ALR-2026-0417", s["inv"])
        except PermissionError:
            pass
        else:
            raise AssertionError("only the Principal Officer may draft an STR (PermissionError)")
        try:
            R.draft_str("ALR-2026-0417", s["po"])
        except ValueError:
            pass
        else:
            raise AssertionError("an STR before approval must raise ValueError")
        agents.decide("ALR-2026-0417", s["po"], "approve", "Structuring and layering confirmed")
        d = R.draft_str("ALR-2026-0417", s["po"])
        assert d["report_ref"] == "STR-DCB-2026-0417", f"report_ref {d['report_ref']!r}"
        assert "6998" not in str(d.get("subject")) or "XXXX" in str(d.get("subject")), "identifiers must stay masked"
        assert d.get("filing_due_by"), "filing_due_by (7 working days) is missing"
        return True

    def dashboard():
        d = R.compute_dashboard([])
        assert d["cases"] == 0 and d["pending_approvals"] == 0, f"empty dashboard {d}"
        assert d["agent_agreement_rate"] is None and d["avg_time_to_close_hours"] is None, "a rate with nothing to divide by is None, never an error"
        d = R.compute_dashboard(list(agents.CASES.values()))
        assert d["cases"] >= 2 and d["alerts_by_band"]["High"] >= 1, f"dashboard {d['cases']} cases, bands {d['alerts_by_band']}"
        return True

    check("T1.2", "explain_case · score, factors, typologies, citations, threshold note", explain)
    check("T1.1", "draft_str · Principal Officer only, after approval, masked, 7-working-day due date", str_rules)
    check("T1.3", "compute_dashboard · empty input does not crash; bands and statuses counted", dashboard)


def task2() -> None:
    print("\nTask 2 · veriguard/operations.py")
    from veriguard import agents, operations as O

    def spans():
        s = ctx()
        tr, bg = O.Tracer(), O.BudgetGuard(O.CASE_BUDGET_USD)
        case = O.run_investigation("ALR-2026-0417", s["inv"], s["index"], tr, bg)
        sp = tr.trace(case["trace_id"])
        assert len(sp) >= 4 and sp[0]["parent_span_id"] is None, f"one trace per investigation: {len(sp)} spans, root parent {sp[0]['parent_span_id']!r}"
        child = [x for x in sp if x["parent_span_id"]]
        assert child and all(x["parent_span_id"] == sp[0]["span_id"] for x in child), "every agent span is a child of the root span"
        a = child[0]["attributes"]
        for k in ("gen_ai.operation.name", "gen_ai.usage.input_tokens", "gen_ai.usage.output_tokens", "veriguard.cost_usd"):
            assert k in a, f"span attribute {k!r} missing (have {sorted(a)})"
        assert 0 < tr.total_cost(case["trace_id"]) <= O.CASE_BUDGET_USD, "the trace cost must be positive and under the cap"
        return True

    def budget():
        b = O.BudgetGuard(0.01)
        assert b.allow(0.004) and b.remaining() == 0.01, "a fresh guard allows spending within the limit"
        b.charge(0.004)
        assert b.remaining() == 0.006 and not b.allow(0.007), f"after 0.004 spent: remaining {b.remaining()}, allow(0.007) must be False"
        assert O.BudgetGuard(0).allow(99) and O.BudgetGuard(0).remaining() == 0.0, "limit 0 means no cap"
        s = ctx()
        stopped = O.run_investigation("ALR-2026-0452", s["inv"], s["index"], O.Tracer(), O.BudgetGuard(0.002))
        assert stopped["status"] == "budget_exceeded", f"a $0.002 cap must stop the investigation, status {stopped['status']!r}"
        return True

    def analysis():
        s = ctx()
        labels = load_labels("error_analysis_labels")
        out = [agents.investigate(l["alert_id"], s["inv"], s["index"]) for l in labels]
        r = O.error_analysis(out, labels)
        assert r["alerts"] == 30 and 0.85 <= r["disposition_accuracy"] <= 1.0, f"alerts {r['alerts']} · disposition accuracy {r['disposition_accuracy']}"
        assert r["escalation_precision"] == 1.0 and r["escalation_recall"] == 1.0, "escalation precision/recall must both be 1.0 on the starter build"
        assert r["top_failure_modes"] and r["taxonomy"], "rank the failure modes of the mismatches"
        return True

    check("T2.1", "trace_step · one trace, child spans, gen_ai.* attributes and cost", spans)
    check("T2.2", "BudgetGuard · allow / charge / remaining; the cap stops an investigation", budget)
    check("T2.3", "error_analysis · accuracy, escalation precision/recall, ranked failure modes", analysis)


def main() -> int:
    args = sys.argv[1:]
    task = args[args.index("--task") + 1] if "--task" in args else "all"
    print("VeriGuard Week 4 self-check (cumulative: run check_week1.py … check_week3.py for the earlier weeks)")
    for key, fn in (("0", task0), ("1", task1), ("2", task2)):
        if task in ("all", key):
            fn()
    return summary(4)


if __name__ == "__main__":
    sys.exit(main())
