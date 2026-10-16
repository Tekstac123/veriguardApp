"""Week 2 · Task 2 — The Supervisor and its specialist agents, case memory, the case file and the HITL checkpoint.

The Supervisor is a raw agent loop (no framework): it follows a plan, routes each step to a specialist, logs every
step, stops at an iteration cap, retries a failed step once and falls back to human review. Specialists reach data
only through call_tool(). Any score ≥ 70 or any escalate recommendation pauses for the Principal Officer.
"""

# ─── WEEK 2 · M2 Agentic Compliance Advisor — you implement the stubbed functions in this file in Week 2 ───
from __future__ import annotations

import datetime as _dt
import json

from .common import (  # noqa: F401 — helpers you will need
    APPROVAL_THRESHOLD,
    LIVE,
    TEMPLATES,
    get_alert,
    load_json,
    now_iso,
    validate_json,
)
from .retrieval import hybrid_search
from .tools import call_tool

CASES: dict[str, dict] = {}  # PROVIDED — the case store (alert_id → case file)
CASE_FILE_SCHEMA = load_json(TEMPLATES / "case_file.schema.json")
PLAN = [
    "transaction_monitoring",
    "risk_assessment",
    "compliance_investigator",
]  # PROVIDED — the Supervisor's plan
INVESTIGATOR_ROLES = {"Investigator", "PrincipalOfficer"}
POLICY_DOC_TYPES = {
    "policy",
    "standard",
    "procedure",
    "methodology",
    "handbook",
    "register",
    "regulatory_digest",
    "circular",
}
FINDING_QUERIES = {  # PROVIDED — what the Compliance Investigator asks the Week 1 knowledge layer
    "structuring": "structuring cash deposits below reporting thresholds across branches",
    "layering": "layering through high-risk jurisdictions inbound SWIFT split",
    "mule": "money mule account many inbound UPI credits transferred out within 24 hours",
    "round_tripping": "round-tripping outbound payments returning from related party common directors",
    "dormant_reactivation": "dormant account reactivation contact details changed",
    "unexplained_wealth_pep": "unexplained wealth PEP large credits source of wealth",
    "Escalate to Principal Officer": "case risk score 70 or above or recommendation to escalate requires Principal Officer approval",
    "Close - False Match Cleared": "potential watchlist match cleared as false match two secondary identifiers",
    "Close - No Further Action": "close investigation with no further action approval authority",
}
APPROVE_CLOSE_HIGH = "Closed - No Further Action"


class CaseMemory:
    """PROVIDED — short-term memory of ONE case. Agents write findings here; nothing is shared between cases."""

    def __init__(self, case_id: str):
        self.case_id = case_id
        self._facts: dict = {}

    def remember(self, key: str, value) -> None:
        self._facts[key] = value

    def recall(self, key: str, default=None):
        return self._facts.get(key, default)

    def facts(self) -> dict:
        return json.loads(json.dumps(self._facts, default=str))


class InvestigatorNotes:
    """PROVIDED — long-term investigator notes per customer, each with a time-to-live (expired notes are invisible)."""

    def __init__(self):
        self._notes: dict[str, list[dict]] = {}

    def add(
        self,
        customer_id: str,
        text: str,
        author: str,
        ttl_days: int = 90,
        now: str | None = None,
    ) -> None:
        created = _dt.datetime.fromisoformat(now or now_iso())
        note = {
            "text": text,
            "author": author,
            "created": created.isoformat(),
            "expires": (created + _dt.timedelta(days=ttl_days)).isoformat(),
        }
        self._notes.setdefault(customer_id, []).append(note)
        if LIVE:  # long-term memory in Blob Storage; a lifecycle-management rule deletes notes after 90 days (TTL)
            from . import azure

            azure.upload_blob(
                "investigator-notes",
                f"{customer_id}/{created.isoformat().replace(':', '')}.json",
                json.dumps(note).encode(),
            )

    def for_customer(self, customer_id: str, now: str | None = None) -> list[dict]:
        at = now or now_iso()
        return [dict(n) for n in self._notes.get(customer_id, []) if n["expires"] > at]


NOTES = InvestigatorNotes()


def persist_case(case: dict) -> None:
    """PROVIDED — live: store the case file in the case-files container (one blob per alert, overwritten on update)."""
    if LIVE:
        from . import azure

        azure.upload_blob(
            "case-files",
            f"{case['alert_id']}.json",
            json.dumps(case, default=str).encode(),
        )


def reset_state() -> None:
    """PROVIDED — empty the case store and the notes (used by the demos and the evaluator)."""
    CASES.clear()
    NOTES._notes.clear()


def transaction_monitoring_agent(alert_id: str, memory: CaseMemory) -> dict:
    """PROVIDED — Transaction Monitoring Agent: typologies through the tool boundary only."""
    found = call_tool("detect_typologies", json.dumps({"alert_id": alert_id}))
    if "error" in found:
        raise RuntimeError(found["error"])
    txns = call_tool(
        "get_transactions", json.dumps({"customer_id": found["customer_id"]})
    )
    memory.remember("customer_id", found["customer_id"])
    memory.remember("typologies", found["typologies"])
    memory.remember(
        "transactions_reviewed",
        [t["txn_id"] for t in txns.get("transactions", [])][-200:],
    )
    return {
        "agent": "transaction_monitoring",
        "typologies": [t["typology"] for t in found["typologies"]],
    }


def risk_assessment_agent(alert_id: str, memory: CaseMemory) -> dict:
    """PROVIDED — Risk Assessment Agent: explains the score the tools compute; it never computes one itself."""
    risk = call_tool("compute_risk_score", json.dumps({"alert_id": alert_id}))
    if "error" in risk:
        raise RuntimeError(risk["error"])
    profile = call_tool(
        "get_customer_profile",
        json.dumps({"customer_id": memory.recall("customer_id")}),
    )
    memory.remember("risk", {k: risk[k] for k in ("score", "band", "factors")})
    memory.remember("screening", risk["screening"])
    memory.remember(
        "profile",
        {
            k: profile.get(k)
            for k in (
                "customer_id",
                "full_name",
                "occupation",
                "risk_category",
                "pep_flag",
                "aadhaar_masked",
                "pan_masked",
                "documents_on_file",
            )
        },
    )
    return {"agent": "risk_assessment", "score": risk["score"], "band": risk["band"]}


def recommend(typologies: list[dict], screening: dict) -> str:
    """PROVIDED — the case recommendation (DCB-SOP-TMI §3, DCB-PRC-SCR §3–4)."""
    if typologies or screening.get("status") == "confirmed":
        return "Escalate to Principal Officer"
    if screening.get("status") == "cleared":
        return "Close - False Match Cleared"
    return "Close - No Further Action"


# ----------------------------------------------------------------------------- Task 2 — you implement
def compliance_investigator(findings: dict, index) -> dict:
    """Compliance Investigator Agent: one current, cited policy clause per finding (Week 1 retrieval, Investigator).

    findings = {"typologies": [names], "recommendation": str}. Returns {"agent", "policy_references":
    [{"finding", "doc_id", "version", "section", "page"}], "narrative": str}.
    """
    refs = []
    for name in list(findings.get("typologies", [])) + [findings.get("recommendation")]:
        query = FINDING_QUERIES.get(name)
        if not query:
            continue
        hits = [
            h
            for h in hybrid_search(index, query, "Investigator", k=5)
            if h.get("doc_type") in POLICY_DOC_TYPES
        ]
        if hits:
            h = hits[0]
            refs.append(
                {
                    "finding": name,
                    "doc_id": h["doc_id"],
                    "version": h["version"],
                    "section": h["section"],
                    "page": h.get("page"),
                }
            )
    narrative = " ".join(
        f"{r['finding']}: {r['doc_id']} v{r['version']} §{r['section']}." for r in refs
    )
    return {
        "agent": "compliance_investigator",
        "policy_references": refs,
        "narrative": narrative,
    }


def investigate(alert_id: str, principal: dict, index, max_steps: int = 8) -> dict:
    """Supervisor raw agent loop: plan → route → log, iteration cap, retry once, fallback to human review; builds a
    schema-valid case file and sets the HITL checkpoint. Stored in CASES[alert_id]."""
    if not INVESTIGATOR_ROLES & set(principal.get("roles", [])):
        raise PermissionError(f"{principal.get('user_id')} may not investigate alerts")
    memory = CaseMemory(alert_id)
    step_log, fallback = [], False
    routes = {
        "transaction_monitoring": lambda: transaction_monitoring_agent(
            alert_id, memory
        ),
        "risk_assessment": lambda: risk_assessment_agent(alert_id, memory),
    }
    queue, steps = list(PLAN), 0
    while queue:
        if steps >= max_steps:
            step_log.append(
                {
                    "step": steps + 1,
                    "agent": queue[0],
                    "status": "stopped: iteration cap",
                }
            )
            fallback = True
            break
        agent = queue.pop(0)
        steps += 1
        if agent == "compliance_investigator":
            if fallback or memory.recall("risk") is None:
                step_log.append(
                    {
                        "step": steps,
                        "agent": agent,
                        "status": "skipped: earlier step failed",
                    }
                )
                continue
            rec = recommend(
                memory.recall("typologies", []), memory.recall("screening", {})
            )
            out = compliance_investigator(
                {
                    "typologies": [
                        t["typology"] for t in memory.recall("typologies", [])
                    ],
                    "recommendation": rec,
                },
                index,
            )
            memory.remember("policy", out)
            step_log.append({"step": steps, "agent": agent, "status": "ok"})
            continue
        for attempt in (1, 2):
            try:
                routes[agent]()
                step_log.append(
                    {
                        "step": steps,
                        "agent": agent,
                        "status": "ok" if attempt == 1 else "ok after retry",
                    }
                )
                break
            except Exception as exc:  # noqa: BLE001 — retry once, then fall back to human review
                if attempt == 2:
                    step_log.append(
                        {"step": steps, "agent": agent, "status": f"failed: {exc}"}
                    )
                    fallback = True
    customer_id = memory.recall("customer_id")
    prior = NOTES.for_customer(customer_id) if customer_id else []
    risk = memory.recall("risk") or {"score": 0, "band": "Low", "factors": []}
    typologies = memory.recall("typologies", [])
    screening = memory.recall("screening", {})
    recommendation = (
        "Escalate to Principal Officer"
        if fallback
        else recommend(typologies, screening)
    )
    hitl_required = (
        recommendation == "Escalate to Principal Officer"
        or risk["score"] >= APPROVAL_THRESHOLD
    )
    mitigating = [
        f["evidence"]
        for f in risk["factors"]
        if f["factor"] == "legit_explanation_verified"
    ]
    if screening.get("status") == "cleared":
        mitigating.append(
            f"potential match {screening['entity_id']} cleared: "
            f"{', '.join(screening['differing_identifiers'])} differ"
        )
    policy = memory.recall("policy") or {"policy_references": [], "narrative": ""}
    rationale = (
        f"Score {risk['score']} ({risk['band']}); typologies: "
        f"{', '.join(t['typology'] for t in typologies) or 'none'}; screening: "
        f"{screening.get('status', 'not run')}. {policy['narrative']}"
        + (
            " Fallback: an agent step failed, routed to human review."
            if fallback
            else ""
        )
    )
    opened = now_iso()
    case = {
        "alert_id": alert_id,
        "customer_id": customer_id,
        "opened_by": principal["user_id"],
        "alert_triggered_at": (get_alert(alert_id) or {}).get("triggered_at"),
        "opened_at": opened,
        "customer_summary": memory.recall("profile") or {},
        "transactions_reviewed": memory.recall("transactions_reviewed", []),
        "typology_assessment": [
            {k: t[k] for k in ("typology", "evidence_txn_ids", "confidence")}
            for t in typologies
        ],
        "risk_score": {
            "score": risk["score"],
            "band": risk["band"],
            "factors": [
                {
                    "factor": f["factor"],
                    "points": f["points"],
                    "evidence": f["evidence"],
                }
                for f in risk["factors"]
            ],
        },
        "policy_references": [
            {k: r[k] for k in ("doc_id", "version", "section", "page")}
            for r in policy["policy_references"]
        ],
        "mitigating_factors": mitigating,
        "recommendation": recommendation,
        "rationale": rationale,
        "hitl": {
            "required": hitl_required,
            "decision": "PENDING" if hitl_required else None,
        },
        "status": "Escalated to Principal Officer"
        if hitl_required
        else "Closed - No Further Action",
        "decisions": [],
        "step_log": step_log,
        "prior_notes": prior,
        "fallback": fallback,
    }
    if not hitl_required:
        case["hitl"].pop("decision")
        case["closed_at"] = opened
    errors = validate_json(case, CASE_FILE_SCHEMA)
    if errors:
        raise ValueError(f"case file failed its schema: {errors[:3]}")
    if customer_id:
        NOTES.add(
            customer_id,
            f"{alert_id}: {recommendation} (score {risk['score']})",
            principal["user_id"],
        )
    CASES[alert_id] = case
    return case


def decide(alert_id: str, principal: dict, decision: str, reason: str) -> dict:
    """Principal Officer checkpoint (DCB-POL-ESC): four-eyes, reason required, approve resumes, reject returns."""
    if "PrincipalOfficer" not in principal.get("roles", []):
        raise PermissionError(
            f"{principal.get('user_id')} is not the Principal Officer"
        )
    case = CASES.get(alert_id)
    if case is None:
        raise KeyError(alert_id)
    if case["opened_by"] == principal["user_id"]:
        raise PermissionError(
            "four-eyes: the officer who opened the case cannot decide it"
        )
    if not case["hitl"].get("required") or case["hitl"].get("decision") != "PENDING":
        raise ValueError(f"{alert_id} is not waiting for a decision")
    if decision not in ("approve", "reject"):
        raise ValueError("decision must be 'approve' or 'reject'")
    if not (reason or "").strip():
        raise ValueError("DCB-POL-ESC §2: the approver's reason must be recorded")
    if decision == "reject":
        case["hitl"]["decision"] = "REJECTED"
        case["status"] = "Under Investigation"
        case["next_step"] = "return_to_investigator"
    else:
        case["hitl"]["decision"] = "APPROVED"
        if case["recommendation"] == "Escalate to Principal Officer":
            case["next_step"] = "regulatory_reporting"
        else:
            case["status"] = APPROVE_CLOSE_HIGH
            case["next_step"] = None
            case["closed_at"] = now_iso()
    case["hitl"]["approver"] = principal["user_id"]
    case["decisions"].append(
        {
            "by": principal["user_id"],
            "decision": decision,
            "reason": reason,
            "at": now_iso(),
        }
    )
    return case
