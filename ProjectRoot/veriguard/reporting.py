"""Week 4 · Task 1 — The end of the workflow: the Regulatory Reporting Agent's STR draft, per-case explainability,
and the risk-scoring dashboard.

An STR is drafted only for an escalation the Principal Officer approved; the draft follows the synthetic FIU-style
schema (datapack/06_templates/str_draft.schema.json) with masked identifiers only. Filing happens outside the system.
"""

# ─── WEEK 4 · L4 Production-Ready + M4 Capstone Defense — you implement the stubbed functions in this file in Week 4 ───
from __future__ import annotations

import datetime as _dt
import html

from .agents import CASES
from .common import (  # noqa: F401 — helpers you will need
    APPROVAL_THRESHOLD, STR_DUE_WORKING_DAYS, TEMPLATES, TYPOLOGY_LABELS, add_working_days,
                     get_account, get_alert, load_json, mask_account, now_iso, validate_json)
from .security import authorize_tool

STR_SCHEMA = load_json(TEMPLATES / "str_draft.schema.json")    # PROVIDED — the official template, unchanged …
# … except one documented relaxation (an FDE finding — raise it as a schema change request): the template assumes an
# individual subject, but companies have no Aadhaar. For non-individual subjects aadhaar_masked is 'NOT APPLICABLE'.
STR_SCHEMA["properties"]["subject"]["properties"]["aadhaar_masked"]["pattern"] = r"^(XXXX XXXX \d{4}|NOT APPLICABLE)$"


# ----------------------------------------------------------------------------- Task 1 — you implement
def draft_str(alert_id: str, principal: dict, trace_id: str | None = None) -> dict:
    """Regulatory Reporting Agent: a schema-valid STR draft for an APPROVED escalation (Principal Officer only).

    Raises PermissionError for the wrong caller, ValueError when the case is not an approved escalation or the
    draft fails STR_SCHEMA. Stores the draft on the case (case["str_draft"]) and returns it.
    """
    authorize_tool(principal, "submit_str_draft")
    case = CASES.get(alert_id)
    if case is None:
        raise KeyError(alert_id)
    if case.get("recommendation") != "Escalate to Principal Officer" or case.get("hitl", {}).get("decision") != "APPROVED":
        raise ValueError("an STR is drafted only for an escalation the Principal Officer approved")
    approval = next(d for d in reversed(case["decisions"]) if d["decision"] == "approve")
    summary = case["customer_summary"]
    account = get_account((get_alert(alert_id) or {}).get("account_id", "")) or {}
    evidence = sorted({i for t in case["typology_assessment"] for i in t["evidence_txn_ids"]})
    from .tools import get_transactions
    txns = [t for t in get_transactions(case["customer_id"])["transactions"] if t["txn_id"] in set(evidence)]
    typologies = [TYPOLOGY_LABELS.get(t["typology"], t["typology"]) for t in case["typology_assessment"]]
    grounds = (f"VeriGuard assembled case {alert_id} for customer {case['customer_id']} ({summary.get('occupation')}). "
               f"Typologies identified: {', '.join(typologies) or 'none'}. "
               + " ".join(f"{f['factor']} (+{f['points']}): {f['evidence']}." for f in case["risk_score"]["factors"]
                          if f["points"] > 0)
               + f" Case risk score {case['risk_score']['score']} ({case['risk_score']['band']}). "
               f"Principal Officer reason: {approval['reason']}")
    draft = {"report_ref": f"STR-DCB-2026-{alert_id[-4:]}", "case_id": alert_id,
             "reporting_entity": "Deccan Commonwealth Bank",
             "subject": {"customer_id": case["customer_id"], "name": summary.get("full_name"),
                         "pan_masked": summary.get("pan_masked"),
                         "aadhaar_masked": summary.get("aadhaar_masked") or "NOT APPLICABLE",
                         "occupation": summary.get("occupation"), "risk_category": summary.get("risk_category")},
             "accounts": [{"account_id": account.get("account_id"),
                           "account_number_masked": mask_account(account.get("account_number")),
                           "branch_code": account.get("branch_code")}],
             "transactions_summary": {"period_from": min((t["txn_timestamp"] for t in txns), default="")[:10],
                                      "period_to": max((t["txn_timestamp"] for t in txns), default="")[:10],
                                      "count": len(txns), "total_value_inr": float(sum(t["amount_inr"] for t in txns)),
                                      "key_transaction_ids": evidence[:20]},
             "grounds_of_suspicion": grounds, "typologies": typologies,
             "risk_score": {"score": case["risk_score"]["score"], "band": case["risk_score"]["band"],
                            "factors": [f"{f['factor']} ({f['points']:+d}): {f['evidence']}"
                                        for f in case["risk_score"]["factors"]]},
             "citations": [{k: r[k] for k in ("doc_id", "version", "section")} for r in case["policy_references"]],
             "approval": {"status": "APPROVED", "approved_by": approval["by"], "approved_at": approval["at"],
                          "reason": approval["reason"]},
             "ai_assistance": {"generated_by": "VeriGuard Regulatory Reporting Agent", "model": "offline-deterministic",
                               "trace_id": trace_id or case.get("trace_id") or ""},
             "filing_due_by": add_working_days(approval["at"], STR_DUE_WORKING_DAYS)}
    errors = validate_json(draft, STR_SCHEMA)
    if errors:
        raise ValueError(f"STR draft failed its schema: {errors[:3]}")
    case["str_draft"] = draft
    case["next_step"] = "principal_officer_files_outside_system"
    return draft


def explain_case(case: dict) -> dict:
    """DCB-MTH-CRR §4 explainability: factor breakdown with evidence (largest first), citations, approval trail.

    Returns {"alert_id", "score", "band", "recommendation", "factors", "typologies", "citations",
             "approval_trail", "threshold_note"}.
    """
    factors = sorted(case["risk_score"]["factors"], key=lambda f: (-f["points"], f["factor"]))
    score = case["risk_score"]["score"]
    note = (f"at or above the {APPROVAL_THRESHOLD}-point threshold: Principal Officer approval required"
            if score >= APPROVAL_THRESHOLD else f"{APPROVAL_THRESHOLD - score} points below the {APPROVAL_THRESHOLD}-point threshold")
    return {"alert_id": case["alert_id"], "score": score, "band": case["risk_score"]["band"],
            "recommendation": case["recommendation"],
            "factors": [{"factor": f["factor"], "points": f["points"], "evidence": f["evidence"]} for f in factors],
            "typologies": [{"typology": t["typology"], "evidence_txn_ids": t["evidence_txn_ids"]}
                           for t in case["typology_assessment"]],
            "citations": [f"{r['doc_id']} v{r['version']} §{r['section']}" for r in case["policy_references"]],
            "approval_trail": [{k: d[k] for k in ("by", "decision", "reason", "at")} for d in case.get("decisions", [])],
            "threshold_note": f"Score {score}/100 — {note}"}


def compute_dashboard(cases: list[dict]) -> dict:
    """Risk-scoring dashboard: alerts by band, time to close (alert trigger → closure), HITL overrides, agent
    agreement (share of human decisions that agreed with the agent) — and one row per case linking the decision to
    its evidence and citations. No customer names or identifiers."""
    by_band = {"Low": 0, "Medium": 0, "High": 0}
    by_status: dict[str, int] = {}
    hours, rows = [], []
    decided = overrides = agree = 0
    for c in cases:
        by_band[c["risk_score"]["band"]] += 1
        by_status[c["status"]] = by_status.get(c["status"], 0) + 1
        start = c.get("alert_triggered_at") or c.get("opened_at")
        if c.get("closed_at") and start:
            hours.append((_dt.datetime.fromisoformat(c["closed_at"]) - _dt.datetime.fromisoformat(start))
                         .total_seconds() / 3600)
        decision = c.get("hitl", {}).get("decision")
        if decision in ("APPROVED", "REJECTED"):
            decided += 1
            overrides += decision == "REJECTED"
            agree += decision == "APPROVED"
        rows.append({"alert_id": c["alert_id"], "band": c["risk_score"]["band"], "score": c["risk_score"]["score"],
                     "recommendation": c["recommendation"], "status": c["status"], "hitl": decision,
                     "evidence_txn_ids": sorted({i for t in c["typology_assessment"] for i in t["evidence_txn_ids"]})[:10],
                     "citations": [f"{r['doc_id']} v{r['version']} §{r['section']}" for r in c["policy_references"]]})
    n = len(cases)
    return {"cases": n, "alerts_by_band": by_band, "by_status": dict(sorted(by_status.items())),
            "pending_approvals": sum(1 for c in cases if c.get("hitl", {}).get("decision") == "PENDING"),
            "avg_time_to_close_hours": round(sum(hours) / len(hours), 2) if hours else None,
            "hitl_decisions": decided, "hitl_override_rate": round(overrides / decided, 3) if decided else 0.0,
            "agent_agreement_rate": round(agree / decided, 3) if decided else None, "rows": rows}


# ----------------------------------------------------------------------------- provided: the workflow UI
def render_dashboard_html(dashboard: dict) -> str:
    """PROVIDED — the dashboard as a self-contained HTML page (reports/dashboard.html)."""
    e = html.escape
    head = "".join(f"<td><b>{e(k)}</b><br>{v}</td>" for k, v in dashboard["alerts_by_band"].items())
    rows = "".join(f"<tr><td>{e(r['alert_id'])}</td><td>{e(r['band'])} ({r['score']})</td><td>{e(r['recommendation'])}"
                   f"</td><td>{e(r['status'])}</td><td>{e(str(r['hitl']))}</td><td>{e(', '.join(r['citations']))}</td>"
                   f"<td>{len(r['evidence_txn_ids'])}</td></tr>" for r in dashboard["rows"])
    return (f"<html><head><meta charset='utf-8'><title>VeriGuard risk dashboard</title></head><body style='font-family:"
            f"Arial'><h2>VeriGuard — risk-scoring dashboard</h2><p>Generated {now_iso()} · {dashboard['cases']} cases · "
            f"HITL override rate {dashboard['hitl_override_rate']} · agent agreement {dashboard['agent_agreement_rate']}"
            f" · pending approvals {dashboard['pending_approvals']}</p><table border=1 cellpadding=6><tr>{head}</tr>"
            f"</table><br><table border=1 cellpadding=4><tr><th>Alert</th><th>Band</th><th>Recommendation</th>"
            f"<th>Status</th><th>HITL</th><th>Citations</th><th>Evidence txns</th></tr>{rows}</table></body></html>")
