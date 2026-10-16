"""Week 4 demo — L4 Production + M4 rehearsal (PROVIDED, do not modify).   python run_week4.py

The workflow (alert queue → investigate → approve / reject → report) with one trace per investigation and the
cost cap, the dashboard (reports/dashboard.html), and error analysis on the 30 labelled alerts.
"""
from __future__ import annotations

from veriguard.common import LIVE, dev_principal, load_labels, make_index, write_report
from veriguard.ingestion import build_corpus


def main() -> None:
    import sys
    if "--azure-check" in sys.argv:
        from veriguard import livecheck
        raise SystemExit(livecheck.main(4))
    try:
        from veriguard.agents import CASES, decide, investigate, reset_state
        from veriguard.operations import (CASE_BUDGET_USD, BudgetGuard, Tracer, error_analysis, run_investigation,
                                          trace_reporting)
        from veriguard.reporting import compute_dashboard, draft_str, explain_case, render_dashboard_html
        from veriguard.tools import set_document_index
        index = make_index(build_corpus())
        set_document_index(index)
        reset_state()
        inv, po = dev_principal("Investigator", "EMP-IN-01"), dev_principal("PrincipalOfficer", "EMP-PO-01")
        tracer, budget = Tracer(), BudgetGuard(CASE_BUDGET_USD)
        case = run_investigation("ALR-2026-0417", inv, index, tracer, budget)
        print(f"ALR-2026-0417 → {case['recommendation']} · {case['risk_score']['score']} · {case['status']}")
        print("  " + explain_case(case)["threshold_note"])
        try:
            draft_str("ALR-2026-0417", po)
        except ValueError as exc:
            print("  STR before approval →", exc)
        decide("ALR-2026-0417", po, "approve", "Structuring and layering confirmed; proceed to STR")
        trace_reporting(tracer, case, budget)
        s = draft_str("ALR-2026-0417", po, case["trace_id"])
        spans = tracer.trace(case["trace_id"])
        print(f"  {s['report_ref']} drafted · due {s['filing_due_by']} · one trace of {len(spans)} spans · cost "
              f"${tracer.total_cost(case['trace_id']):.6f} (cap ${CASE_BUDGET_USD})")
        stopped = run_investigation("ALR-2026-0452", inv, index, Tracer(), BudgetGuard(0.002))
        print("  Budget $0.002 on ALR-2026-0452 →", stopped["status"], f"after {stopped['steps_completed']} steps")
        labels = load_labels("error_analysis_labels")
        outputs = [investigate(l["alert_id"], inv, index) for l in labels]
        ea = error_analysis(outputs, labels)
        print(f"\nError analysis (30 alerts): disposition {ea['disposition_accuracy']:.0%} · score {ea['score_accuracy']:.0%}"
              f" · escalation precision {ea['escalation_precision']} recall {ea['escalation_recall']}")
        print("  Top failure modes:", ea["top_failure_modes"])
        dash = compute_dashboard(list(CASES.values()))
        print(f"\nDashboard: {dash['cases']} cases · by band {dash['alerts_by_band']} · pending {dash['pending_approvals']}")
        path = write_report(ea, "week4_error_analysis.json")
        (path.parent / "dashboard.html").write_text(render_dashboard_html(dash), encoding="utf-8")
        print("Reports →", path.name, "· dashboard.html")
        if LIVE:
            import json
            from veriguard import azure
            azure.upload_blob("str-drafts", f"{s['report_ref']}.json", json.dumps(s).encode())
            print(f"LIVE · {tracer.export()} spans sent to Application Insights · {s['report_ref']} in str-drafts")
    except NotImplementedError as exc:
        print(f"Not finished yet: {exc}")


if __name__ == "__main__":
    main()
