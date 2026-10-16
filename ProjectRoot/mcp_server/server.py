"""VeriGuard Compliance Tools — MCP server for Azure Container Apps (Week 2, PROVIDED, do not modify).

Exposes YOUR Week 2 tools over MCP streamable HTTP at /mcp. Every call goes through your call_tool(), so the tool
contracts (TOOL_SCHEMAS) are enforced on the server — an agent can never send raw SQL or an extra argument.

Auth: every request must carry x-api-key = MCP_API_KEY (a Container App secret referenced from Azure Key Vault; the
Foundry project connection veriguard-tools-mcp sends the same value). On start-up, when VERIGUARD_MODE=live, the server
downloads dcb_core.sql from the core-banking container with its managed identity (Storage Blob Data Reader).

    uvicorn mcp_server.server:app --host 0.0.0.0 --port 8080          # local test (MCP_API_KEY in .env)
"""
from __future__ import annotations

import hmac
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp.server.mcpserver import MCPServer  # noqa: E402
from starlette.middleware.base import BaseHTTPMiddleware  # noqa: E402
from starlette.responses import JSONResponse  # noqa: E402


def _sync_core_banking() -> None:
    from veriguard import common
    if not common.LIVE or (common.AZURE_CACHE / "02_structured_data" / "dcb_core.sql").exists():
        return
    from veriguard import azure
    dest = common.AZURE_CACHE / "02_structured_data"
    dest.mkdir(parents=True, exist_ok=True)
    for name in azure.list_blobs("core-banking"):
        (dest / Path(name).name).write_bytes(azure.download_blob("core-banking", name))
    common.STRUCTURED = dest


_sync_core_banking()
from veriguard.tools import call_tool  # noqa: E402  (imported after the sync so STRUCTURED points at the cache)

server = MCPServer("veriguard-compliance-tools", instructions=(
    "DCB VeriGuard compliance tools. Numbers come from these tools, never from the model. All outputs are masked."))


def _call(name: str, **arguments) -> dict:
    return call_tool(name, json.dumps({k: v for k, v in arguments.items() if v is not None}))


@server.tool(description="Transactions of a customer (read-only, txn-db). Dates are YYYY-MM-DD.")
def get_transactions(customer_id: str, from_date: str | None = None, to_date: str | None = None) -> dict:
    return _call("get_transactions", customer_id=customer_id, from_date=from_date, to_date=to_date)


@server.tool(description="Masked KYC profile of a customer (kyc-service).")
def get_customer_profile(customer_id: str) -> dict:
    return _call("get_customer_profile", customer_id=customer_id)


@server.tool(description="Whether a name has adverse media coverage (kyc-service).")
def get_adverse_media(name: str) -> dict:
    return _call("get_adverse_media", name=name)


@server.tool(description="Screen a customer against the sanctions and internal-negative lists (DCB-PRC-SCR).")
def screen_watchlist(customer_id: str) -> dict:
    return _call("screen_watchlist", customer_id=customer_id)


@server.tool(description="Typologies (structuring, layering, mule, round-tripping …) in an alert's review period.")
def detect_typologies(alert_id: str) -> dict:
    return _call("detect_typologies", alert_id=alert_id)


@server.tool(description="Explainable DCB-MTH-CRR risk score (0-100), band and factors for an alert.")
def compute_risk_score(alert_id: str) -> dict:
    return _call("compute_risk_score", alert_id=alert_id)


class ApiKeyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if request.url.path == "/health":
            return JSONResponse({"status": "ok", "service": "veriguard-compliance-tools"})
        expected = os.getenv("MCP_API_KEY", "")
        given = request.headers.get("x-api-key", "")
        if not expected or not hmac.compare_digest(expected, given):
            return JSONResponse({"error": "missing or invalid x-api-key"}, status_code=401)
        return await call_next(request)


app = server.streamable_http_app(stateless_http=True, json_response=True, host="0.0.0.0")
app.add_middleware(ApiKeyMiddleware)
