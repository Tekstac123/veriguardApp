"""Week 2 · Task 1 — VeriGuard's enterprise tools, exposed as three MCP-style servers with strict tool contracts.

    txn-db               get_transactions                         (read-only core-banking transactions)
    kyc-service          get_customer_profile · get_adverse_media (PII always masked)
    watchlist-screening  screen_watchlist                         (DCB-PRC-SCR)
    analytics            detect_typologies · compute_risk_score   (DCB-HB-TYP, DCB-MTH-CRR)
    docs                 search_documents                         (the Week 1 retrieval layer)

Numbers come from tools, never from an agent. Agents reach every tool through call_tool(), which enforces the
contract in TOOL_SCHEMAS — the same JSON schema an MCP server publishes.
"""

# ─── WEEK 2 · M2 Agentic Compliance Advisor — you implement the stubbed functions in this file in Week 2 ───
from __future__ import annotations

import datetime as _dt
import json

from .common import (  # noqa: F401 — helpers you will need
    CTR_THRESHOLD, POINTS, SCORED_TYPOLOGIES, adverse_media_names, band_of, get_account, get_alert,
                     get_customer, high_risk_jurisdictions, legit_explanation, mask_aadhaar, mask_pan,
                     name_similarity, normalise_name, related_parties, review_transactions, transactions, ts,
                     validate_json, velocity_anomaly, watchlist)

_DOCUMENT_INDEX = {"index": None}
ID = {"type": "string", "pattern": r"^CUST-\d{6}$"}
ALERT = {"type": "string", "pattern": r"^ALR-2026-[0-9A-Z]{3,4}$"}
DATE = {"type": "string", "pattern": r"^\d{4}-\d{2}-\d{2}$"}
MCP_SERVERS = {"txn-db": ["get_transactions"], "kyc-service": ["get_customer_profile", "get_adverse_media"],
               "watchlist-screening": ["screen_watchlist"], "analytics": ["detect_typologies", "compute_risk_score"],
               "docs": ["search_documents"]}
TOOL_SCHEMAS = {   # PROVIDED — each tool's argument contract (additionalProperties False: no extra arguments)
    "get_transactions": {"type": "object", "required": ["customer_id"], "additionalProperties": False,
                         "properties": {"customer_id": ID, "from_date": DATE, "to_date": DATE}},
    "get_customer_profile": {"type": "object", "required": ["customer_id"], "additionalProperties": False,
                             "properties": {"customer_id": ID}},
    "get_adverse_media": {"type": "object", "required": ["name"], "additionalProperties": False,
                          "properties": {"name": {"type": "string", "pattern": r"^.{2,120}$"}}},
    "screen_watchlist": {"type": "object", "required": ["customer_id"], "additionalProperties": False,
                         "properties": {"customer_id": ID}},
    "detect_typologies": {"type": "object", "required": ["alert_id"], "additionalProperties": False,
                          "properties": {"alert_id": ALERT}},
    "compute_risk_score": {"type": "object", "required": ["alert_id"], "additionalProperties": False,
                           "properties": {"alert_id": ALERT}},
    "search_documents": {"type": "object", "required": ["query", "role"], "additionalProperties": False,
                         "properties": {"query": {"type": "string", "pattern": r"^.{3,300}$"},
                                        "role": {"type": "string", "pattern": r"^[A-Za-z]+$"}}},
}


# ----------------------------------------------------------------------------- provided tools
def get_transactions(customer_id: str, from_date: str | None = None, to_date: str | None = None) -> dict:
    """PROVIDED — txn-db: parameterised, read-only. Raw SQL is never accepted."""
    rows = transactions(customer_id, from_date, (to_date + "T23:59:59") if to_date else None)
    keep = ("txn_id", "txn_timestamp", "channel", "direction", "amount_inr", "branch_code", "counterparty_name",
            "counterparty_country", "narration")
    return {"customer_id": customer_id, "count": len(rows), "transactions": [{k: r[k] for k in keep} for r in rows]}


def get_customer_profile(customer_id: str) -> dict:
    """PROVIDED — kyc-service: the KYC view an investigation needs, every identifier masked (DCB-STD-DCP §2)."""
    c = get_customer(customer_id)
    if not c:
        return {"customer_id": customer_id, "error": "unknown customer"}
    keep = ("full_name", "customer_type", "segment", "occupation", "annual_income_declared_inr",
            "expected_monthly_volume_inr", "risk_category", "pep_flag", "state", "home_branch", "onboarding_date",
            "kyc_last_updated", "documents_on_file")
    return {"customer_id": customer_id, **{k: c[k] for k in keep}, "aadhaar_masked": mask_aadhaar(c["aadhaar_number"]),
            "pan_masked": mask_pan(c["pan"]), "phone": "[REDACTED]", "email": "[REDACTED]", "address": "[REDACTED]"}


def get_adverse_media(name: str) -> dict:
    """PROVIDED — kyc-service: whether the name has adverse media coverage."""
    return {"name": name, "adverse": normalise_name(name) in adverse_media_names()}


def search_documents(query: str, role: str) -> dict:
    """PROVIDED — docs: the Week 1 retrieval layer, trimmed to the caller's role. Needs set_document_index()."""
    from .retrieval import hybrid_search
    if _DOCUMENT_INDEX["index"] is None:
        return {"error": "document index not set"}
    hits = hybrid_search(_DOCUMENT_INDEX["index"], query, role, k=5)
    return {"results": [{k: h[k] for k in ("doc_id", "version", "section", "page", "heading", "text")} for h in hits]}


def set_document_index(index) -> None:
    """PROVIDED — give the docs server the SearchIndex built in Week 1."""
    _DOCUMENT_INDEX["index"] = index


def screen_watchlist(customer_id: str) -> dict:
    """PROVIDED — watchlist-screening tool wrapper around your screen_customer()."""
    return screen_customer(customer_id)


def indicator_typologies(alert: dict, customer: dict) -> list[dict]:
    """PROVIDED — the two unscored indicators (DCB-HB-TYP §5–6): dormant reactivation and unexplained PEP wealth."""
    out = []
    account = get_account(alert["account_id"]) or {}
    if "reactivated" in (account.get("status") or "").lower():
        out.append({"typology": "dormant_reactivation", "evidence_txn_ids": [], "confidence": "Medium",
                    "summary": f"account {account.get('status')}"})
    if customer.get("pep_flag") == "Y" and velocity_anomaly(alert)["anomaly"] and not legit_explanation(customer):
        out.append({"typology": "unexplained_wealth_pep", "evidence_txn_ids": [], "confidence": "Medium",
                    "summary": "large credits to a PEP without documented source of wealth"})
    return out


# ----------------------------------------------------------------------------- Task 1 — you implement
def detect_typologies(alert_id: str) -> dict:
    """Typologies in the alert's 90-day review period (DCB-HB-TYP, DCB-CC-2026-07), each with evidence txn ids.

    Returns {"alert_id", "customer_id", "typologies": [{"typology", "evidence_txn_ids", "confidence", "summary"}]};
    an unknown alert returns {"alert_id", "error": "unknown alert"}. Add indicator_typologies(...) at the end.
    """
    alert = get_alert(alert_id)
    if not alert:
        return {"alert_id": alert_id, "error": "unknown alert"}
    rows = review_transactions(alert)
    customer = get_customer(alert["customer_id"]) or {}
    found = []

    def add(name, evidence, summary, confidence="High"):
        found.append({"typology": name, "evidence_txn_ids": evidence, "confidence": confidence, "summary": summary})

    near = [r for r in rows if r["channel"] == "CASH_DEPOSIT" and 0.9 * CTR_THRESHOLD <= r["amount_inr"] < CTR_THRESHOLD]
    best: list[dict] = []
    for i, first in enumerate(near):
        window = [r for r in near[i:] if ts(r) - ts(first) <= _dt.timedelta(days=10)]
        if len(window) > len(best):
            best = window
    if len(best) >= 3 and len({r["branch_code"] for r in best}) >= 3:
        add("structuring", [r["txn_id"] for r in best],
            f"{len(best)} cash deposits of Rs 9-10 lakh across {len({r['branch_code'] for r in best})} branches "
            f"within 10 days, each just below the Rs 10 lakh CTR threshold")

    hrj = high_risk_jurisdictions()
    swift = [r for r in rows if r["channel"] in ("SWIFT_IN", "SWIFT_OUT") and r["counterparty_country"] in hrj]
    if swift:
        add("layering", [r["txn_id"] for r in swift],
            f"{len(swift)} SWIFT transfer(s) with {', '.join(sorted({hrj[r['counterparty_country']] for r in swift}))} "
            f"(High-Risk Jurisdiction Register)")

    inbound = [r for r in rows if r["channel"] in ("UPI", "IMPS") and r["direction"] == "CR"]
    mule = None
    for i, first in enumerate(inbound):
        window = [r for r in inbound[i:] if ts(r) - ts(first) <= _dt.timedelta(days=7)]
        if len({r["counterparty_name"] for r in window}) >= 25:
            credited = sum(r["amount_inr"] for r in window)
            out = [r for r in rows if r["direction"] == "DR" and ts(first) <= ts(r) <= ts(window[-1]) + _dt.timedelta(hours=24)]
            if sum(r["amount_inr"] for r in out) >= 0.8 * credited:
                mule = ([r["txn_id"] for r in window + out],
                        f"{len({r['counterparty_name'] for r in window})} distinct UPI/IMPS senders in 7 days, "
                        f"{sum(r['amount_inr'] for r in out) / credited:.0%} sent out within 24 hours (DCB-CC-2026-07)")
                break
    if mule is None:
        cycles = []
        for c in (r for r in inbound if r["amount_inr"] >= 100_000):
            out = [r for r in rows if r["direction"] == "DR" and r["channel"] in ("UPI", "IMPS")
                   and _dt.timedelta(0) < ts(r) - ts(c) <= _dt.timedelta(hours=24) and r["amount_inr"] >= 0.8 * c["amount_inr"]]
            if out:
                cycles += [c["txn_id"], out[0]["txn_id"]]
        if len(cycles) >= 4:
            mule = (cycles, f"{len(cycles) // 2} pass-through cycles: credit followed by ≥ 80% out within 24 hours")
    if mule:
        add("mule", *mule)

    rel = related_parties(customer)
    if rel:
        evidence = []
        for o in (r for r in rows if r["direction"] == "DR" and normalise_name(r["counterparty_name"]) in rel):
            back = [r for r in rows if r["direction"] == "CR" and normalise_name(r["counterparty_name"]) in rel
                    and _dt.timedelta(0) < ts(r) - ts(o) <= _dt.timedelta(days=30)
                    and 0.9 * o["amount_inr"] <= r["amount_inr"] <= o["amount_inr"]]
            if back:
                evidence += [o["txn_id"], back[0]["txn_id"]]
        if len(evidence) >= 4:
            add("round_tripping", evidence, f"{len(evidence) // 2} cycles out to and ~90-100% back from related parties "
                                            f"sharing a director within 30 days")

    found += indicator_typologies(alert, customer)
    return {"alert_id": alert_id, "customer_id": alert["customer_id"], "typologies": found}


def screen_customer(customer_id: str) -> dict:
    """DCB-PRC-SCR: best SANCTIONS / INTERNAL_NEGATIVE match ≥ 0.85, classified confirmed / unresolved / cleared.

    Returns {"customer_id", "status": "no_match" | "cleared" | "unresolved" | "confirmed", "entity_id",
             "similarity", "differing_identifiers"}.
    """
    c = get_customer(customer_id)
    if not c:
        return {"customer_id": customer_id, "error": "unknown customer"}
    best = None
    for w in watchlist():
        for name in [w["name"]] + [a for a in (w["aliases"] or "").split(";") if a.strip()]:
            score = name_similarity(c["full_name"], name)
            if score >= 0.85 and (best is None or score > best[0]):
                best = (score, w)
    if best is None:
        return {"customer_id": customer_id, "status": "no_match", "entity_id": None, "similarity": None,
                "differing_identifiers": []}
    score, w = best
    differing = [k for k, mine, theirs in (("date_of_birth", c["date_of_birth"], w["date_of_birth"]),
                                           ("nationality", c["nationality"], w["nationality"]))
                 if mine and theirs and mine != theirs]
    if score == 1.0 and c["date_of_birth"] == w["date_of_birth"]:
        status = "confirmed"
    elif len(differing) >= 2:
        status = "cleared"
    else:
        status = "unresolved"
    return {"customer_id": customer_id, "status": status, "entity_id": w["entity_id"], "similarity": score,
            "differing_identifiers": differing}


def compute_risk_score(alert_id: str) -> dict:
    """DCB-MTH-CRR explainable 0–100 score: factors with points and evidence, capped at 100, floored at 0, banded.

    Returns {"alert_id", "customer_id", "score", "band", "factors": [{"factor", "points", "evidence"}],
             "typologies", "screening"}.
    """
    alert = get_alert(alert_id)
    if not alert:
        return {"alert_id": alert_id, "error": "unknown alert"}
    c = get_customer(alert["customer_id"])
    rows = review_transactions(alert)
    factors = [{"factor": f"kyc_{c['risk_category']}", "points": POINTS[f"kyc_{c['risk_category']}"],
                "evidence": f"KYC risk category {c['risk_category']}"}]
    if c["pep_flag"] == "Y":
        factors.append({"factor": "pep", "points": POINTS["pep"], "evidence": "customer is a PEP or PEP associate"})
    screening = screen_customer(c["customer_id"])
    if screening["status"] == "confirmed":
        factors.append({"factor": "watchlist_confirmed", "points": POINTS["watchlist_confirmed"],
                        "evidence": f"confirmed match {screening['entity_id']}"})
    elif screening["status"] == "unresolved":
        factors.append({"factor": "watchlist_unresolved", "points": POINTS["watchlist_unresolved"],
                        "evidence": f"unresolved potential match {screening['entity_id']} ({screening['similarity']})"})
    hrj = high_risk_jurisdictions()
    exposure = [r["txn_id"] for r in rows if r["counterparty_country"] in hrj]
    if exposure:
        factors.append({"factor": "hrj_exposure", "points": POINTS["hrj_exposure"],
                        "evidence": f"{len(exposure)} transaction(s) with high-risk jurisdictions"})
    velocity = velocity_anomaly(alert)
    if velocity["anomaly"]:
        factors.append({"factor": "velocity_anomaly", "points": POINTS["velocity_anomaly"],
                        "evidence": f"30-day turnover Rs {velocity['turnover_30d']:,.0f} > 3 x baseline "
                                    f"Rs {velocity['baseline_monthly']:,.0f}"})
    typologies = detect_typologies(alert_id)["typologies"]
    for t in [t for t in typologies if t["typology"] in SCORED_TYPOLOGIES][:2]:
        factors.append({"factor": f"typology:{t['typology']}", "points": POINTS["typology"], "evidence": t["summary"]})
    names = adverse_media_names()
    if normalise_name(c["full_name"]) in names or any(r["direction"] == "CR" and normalise_name(r["counterparty_name"])
                                                      in names for r in rows):
        factors.append({"factor": "adverse_media", "points": POINTS["adverse_media"],
                        "evidence": "adverse media on the customer or a remitter"})
    explanation = legit_explanation(c)
    if explanation:
        factors.append({"factor": "legit_explanation_verified", "points": POINTS["legit_explanation_verified"],
                        "evidence": explanation})
    score = max(0, min(100, sum(f["points"] for f in factors)))
    return {"alert_id": alert_id, "customer_id": c["customer_id"], "score": score, "band": band_of(score),
            "factors": factors, "typologies": typologies, "screening": screening}


def call_tool(name: str, arguments_json: str) -> dict:
    """The MCP tool boundary: JSON arguments validated against TOOL_SCHEMAS, then the tool runs. Never raises."""
    schema = TOOL_SCHEMAS.get(name)
    if schema is None:
        return {"error": f"unknown tool '{name}'"}
    try:
        args = json.loads(arguments_json)
    except (TypeError, ValueError):
        return {"error": "arguments are not valid JSON"}
    problems = validate_json(args, schema)
    if problems:
        return {"error": "invalid arguments: " + "; ".join(problems)}
    try:
        return globals()[name](**args)
    except Exception as exc:  # noqa: BLE001 — a tool failure is data the agent can act on
        return {"error": f"tool '{name}' failed: {type(exc).__name__}"}
