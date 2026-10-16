"""Week 2 demo — M2 Agentic Compliance Advisor (PROVIDED, do not modify).   python run_week2.py

Investigates the three M2 test alerts (datapack/03_alerts/m2_test_alerts_labels.csv), compares each with its label,
runs the Principal Officer checkpoint, and checks memory isolation. Writes reports/week2_case_files.json.
"""
from __future__ import annotations

from veriguard.common import LIVE, dev_principal, load_labels, make_index, write_report
from veriguard.ingestion import build_corpus


def main() -> None:
    import sys
    if "--azure-check" in sys.argv:
        from veriguard import livecheck
        raise SystemExit(livecheck.main(2))
    try:
        from veriguard.agents import CASES, decide, investigate, persist_case, reset_state
        from veriguard.tools import set_document_index
        index = make_index(build_corpus())
        set_document_index(index)
        reset_state()
        inv, po = dev_principal("Investigator", "EMP-IN-01"), dev_principal("PrincipalOfficer", "EMP-PO-01")
        correct = 0
        for lab in load_labels("m2_test_alerts_labels"):
            case = investigate(lab["alert_id"], inv, index)
            persist_case(case)
            ok = case["recommendation"] == lab["expected_disposition"] and \
                case["risk_score"]["score"] == int(lab["expected_risk_score"])
            correct += ok
            print(f"{'✔' if ok else '✘'} {lab['alert_id']}: {case['recommendation']} · score {case['risk_score']['score']} "
                  f"{case['risk_score']['band']} · HITL {case['hitl']} (expected {lab['expected_disposition']}, "
                  f"{lab['expected_risk_score']})")
            print("    steps " + " → ".join(f"{s['agent']}:{s['status']}" for s in case["step_log"])
                  + " · policy " + ", ".join(f"{r['doc_id']} §{r['section']}" for r in case["policy_references"]))
        print(f"\nM2 test alerts correct: {correct}/3")
        print("PO approves ALR-2026-0417 →", decide("ALR-2026-0417", po, "approve", "Structuring and SWIFT to KSI "
                                                    "confirmed")["next_step"])
        try:
            decide("ALR-2026-0417", inv, "approve", "x")
        except PermissionError as exc:
            print("Investigator tries to approve →", exc)
        print("Memory isolation: ALR-2026-0452 case memory mentions CUST-100417? →",
              "CUST-100417" in str(CASES["ALR-2026-0452"]))
        write_report(CASES, "week2_case_files.json")
        if LIVE:
            print("LIVE · case files in the case-files container, investigator notes in investigator-notes (90-day TTL)")
    except NotImplementedError as exc:
        print(f"Not finished yet: {exc}")


if __name__ == "__main__":
    main()
