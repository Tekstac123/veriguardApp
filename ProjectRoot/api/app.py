"""VeriGuard API — every week's code behind one authenticated endpoint on Azure Container Apps (Week 4, PROVIDED).

Authentication: Container Apps built-in authentication (Microsoft Entra ID, "Require authentication") validates the
caller's token signature before the request reaches this app and forwards the claims in X-MS-CLIENT-PRINCIPAL. This app
then runs YOUR principal_from_claims (tenant, audience, validity window, app roles) and YOUR controls on every call:
secure_ask (Week 1 + 3), investigate / decide (Week 2), draft_str and the dashboard (Week 4), with the audit log in the
immutable audit-log container and one trace per investigation in Application Insights.

    uvicorn api.app:app --port 8000          # local: send a bearer token from: az account get-access-token --resource api://veriguard-api (dev only)
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI, Header, HTTPException, Request  # noqa: E402
from fastapi.responses import HTMLResponse, RedirectResponse  # noqa: E402

from veriguard import agents, governance, operations, reporting  # noqa: E402
from veriguard.common import make_index  # noqa: E402
from veriguard.ingestion import build_corpus  # noqa: E402
from veriguard.security import principal_from_claims  # noqa: E402
from veriguard.tools import set_document_index  # noqa: E402

app = FastAPI(title="VeriGuard API", version="1.0")
STATE: dict = {}


def index():
    if "index" not in STATE:
        STATE["index"] = make_index(build_corpus())
        set_document_index(STATE["index"])
        STATE["audit"] = governance.AuditLog()
    return STATE["index"]


def principal(request: Request, authorization: str | None) -> dict:
    """Claims from Easy Auth (X-MS-CLIENT-PRINCIPAL) — or, only when ALLOW_DEV_BEARER=1 locally, an unverified bearer
    token. Your principal_from_claims decides; a PermissionError becomes 401/403."""
    header = request.headers.get("x-ms-client-principal")
    if header:
        data = json.loads(base64.b64decode(header))
        claims: dict = {}
        for c in data.get("claims", []):
            typ = c["typ"].rsplit("/", 1)[-1]
            key = {
                "tenantid": "tid",
                "objectidentifier": "oid",
                "role": "roles",
                "roles": "roles",
                "groups": "groups",
            }.get(typ, typ)
            if key in ("roles", "groups"):
                claims.setdefault(key, []).append(c["val"])
            elif key in ("exp", "nbf", "iat"):
                claims[key] = int(c["val"])
            else:
                claims[key] = c["val"]
    elif (
        os.getenv("ALLOW_DEV_BEARER") == "1"
        and authorization
        and authorization.startswith("Bearer ")
    ):
        p = authorization.split()[1].split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    else:
        raise HTTPException(401, "sign in with Microsoft Entra ID")
    try:
        return principal_from_claims(claims, int(time.time()))
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc


@app.get("/", include_in_schema=False)
def home() -> RedirectResponse:
    """Browser landing page: send signed-in users to the Swagger page (POST /ask lives there)."""
    return RedirectResponse(url="/docs")


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "service": "veriguard-api",
        "mode": os.getenv("VERIGUARD_MODE", "offline"),
    }


@app.get("/ready")
def ready() -> dict:
    """Readiness probe for Azure Container Apps: the index is built and the audit log is ready."""
    index()
    return {"status": "ready", "chunks": len(STATE["index"].chunks)}


@app.post("/ask")
def ask(
    body: dict, request: Request, authorization: str | None = Header(default=None)
) -> dict:
    p = principal(request, authorization)
    try:
        return governance.secure_ask(index(), body["question"], p, STATE["audit"])
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc


@app.post("/investigate/{alert_id}")
def investigate(
    alert_id: str, request: Request, authorization: str | None = Header(default=None)
) -> dict:
    p = principal(request, authorization)
    tracer, budget = (
        operations.Tracer(),
        operations.BudgetGuard(operations.CASE_BUDGET_USD),
    )
    try:
        case = operations.run_investigation(alert_id, p, index(), tracer, budget)
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    STATE["audit"].append(
        "tool_call",
        p,
        {"tool": "investigate", "alert_id": alert_id, "status": case.get("status")},
    )
    tracer.export()
    if "risk_score" in case:
        agents.persist_case(case)
    return case


@app.post("/decide/{alert_id}")
def decide(
    alert_id: str,
    body: dict,
    request: Request,
    authorization: str | None = Header(default=None),
) -> dict:
    p = principal(request, authorization)
    try:
        case = agents.decide(
            alert_id, p, body.get("decision", ""), body.get("reason", "")
        )
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except (KeyError, ValueError) as exc:
        raise HTTPException(409, str(exc)) from exc
    STATE["audit"].append(
        "approval",
        p,
        {
            "alert_id": alert_id,
            "decision": body.get("decision"),
            "reason": body.get("reason"),
        },
    )
    agents.persist_case(case)
    return case


@app.post("/str/{alert_id}")
def str_draft(
    alert_id: str, request: Request, authorization: str | None = Header(default=None)
) -> dict:
    p = principal(request, authorization)
    try:
        draft = reporting.draft_str(
            alert_id, p, agents.CASES.get(alert_id, {}).get("trace_id")
        )
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except (KeyError, ValueError) as exc:
        raise HTTPException(409, str(exc)) from exc
    from veriguard.common import LIVE

    if LIVE:
        from veriguard import azure

        azure.upload_blob(
            "str-drafts", f"{draft['report_ref']}.json", json.dumps(draft).encode()
        )
    STATE["audit"].append(
        "tool_call", p, {"tool": "submit_str_draft", "report_ref": draft["report_ref"]}
    )
    return draft


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(
    request: Request, authorization: str | None = Header(default=None)
) -> str:
    principal(request, authorization)
    return reporting.render_dashboard_html(
        reporting.compute_dashboard(list(agents.CASES.values()))
    )
