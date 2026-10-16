"""Week 4 · Task 2 — Observability, cost governance and error analysis.

One OpenTelemetry-style trace spans a whole investigation, alert to report, with the GenAI semantic-convention
attributes on every span and a cost on every model step; a budget guard stops an investigation before it overspends;
error analysis compares VeriGuard's outputs with the 30 labelled alerts and builds a failure taxonomy.
"""

# ─── WEEK 4 · L4 Production-Ready + M4 Capstone Defense — you implement the stubbed functions in this file in Week 4 ───
from __future__ import annotations

import hashlib

from .agents import investigate
from .common import PRICE_INPUT_PER_1K, PRICE_OUTPUT_PER_1K, TYPOLOGY_LABELS, now_iso

# PROVIDED — tokens and latency each agent step uses (measured on the live pilot), for offline cost estimation.
AGENT_TOKEN_PROFILE = [("supervisor", 900, 120, 800.0), ("transaction_monitoring", 1800, 150, 2100.0),
                       ("risk_assessment", 2700, 230, 4380.0), ("compliance_investigator", 3200, 300, 3650.0)]
REPORTING_PROFILE = ("regulatory_reporting", 2600, 700, 5200.0)
CASE_BUDGET_USD = 0.01           # the per-investigation cap signed off at M2 (cost estimate × 1.5)


class Tracer:
    """PROVIDED — collects spans (stand-in for the OpenTelemetry exporter to Azure Monitor / Application Insights)."""

    def __init__(self, price_input_per_1k: float = PRICE_INPUT_PER_1K, price_output_per_1k: float = PRICE_OUTPUT_PER_1K):
        self.price_in, self.price_out = price_input_per_1k, price_output_per_1k
        self.spans: list[dict] = []

    def start_trace(self, alert_id: str) -> tuple[str, str]:
        """Start one trace for an investigation; returns (trace_id, root_span_id). The root span is recorded."""
        trace_id = hashlib.sha256(f"{alert_id}:{now_iso()}:{len(self.spans)}".encode()).hexdigest()[:32]
        root = {"trace_id": trace_id, "span_id": trace_id[:16], "parent_span_id": None, "name": "veriguard.investigation",
                "attributes": {"veriguard.alert_id": alert_id, "gen_ai.operation.name": "invoke_workflow"}}
        self.spans.append(root)
        return trace_id, root["span_id"]

    def trace(self, trace_id: str) -> list[dict]:
        return [s for s in self.spans if s["trace_id"] == trace_id]

    def export(self) -> int:
        """Live: send every span to Application Insights (one OpenTelemetry trace per investigation)."""
        from .common import LIVE
        if not LIVE:
            return 0
        from . import azure
        return azure.export_spans(self.spans)

    def total_cost(self, trace_id: str | None = None) -> float:
        spans = self.trace(trace_id) if trace_id else self.spans
        return round(sum(s["attributes"].get("veriguard.cost_usd", 0.0) for s in spans), 6)


# ----------------------------------------------------------------------------- Task 2 — you implement
def trace_step(tracer: Tracer, trace_id: str, parent_span_id: str, agent_name: str, input_tokens: int,
               output_tokens: int, latency_ms: float, status: str = "ok") -> dict:
    """One child span of the investigation trace, with GenAI semantic-convention attributes and its cost."""
    cost = round(input_tokens / 1000 * tracer.price_in + output_tokens / 1000 * tracer.price_out, 6)
    span_id = hashlib.sha256(f"{trace_id}:{len(tracer.spans)}:{agent_name}".encode()).hexdigest()[:16]
    span = {"trace_id": trace_id, "span_id": span_id, "parent_span_id": parent_span_id,
            "name": f"veriguard.agent.{agent_name}",
            "attributes": {"gen_ai.operation.name": "invoke_agent", "gen_ai.agent.name": agent_name,
                           "gen_ai.usage.input_tokens": input_tokens, "gen_ai.usage.output_tokens": output_tokens,
                           "gen_ai.response.finish_reasons": [status], "veriguard.latency_ms": latency_ms,
                           "veriguard.cost_usd": cost, "veriguard.status": status}}
    tracer.spans.append(span)
    return span


class BudgetGuard:
    """Per-investigation cost cap (Foundry Control Plane stand-in). limit_usd 0 means no cap."""

    def __init__(self, limit_usd: float):
        self.limit_usd = float(limit_usd)
        self.spent = 0.0

    def allow(self, estimate_usd: float) -> bool:
        """True when spending estimate_usd now would not take the investigation over the limit (0 = no cap)."""
        return self.limit_usd <= 0 or self.spent + estimate_usd <= self.limit_usd + 1e-12

    def charge(self, actual_usd: float) -> None:
        """Record money actually spent."""
        self.spent += actual_usd

    def remaining(self) -> float:
        """Budget left (never below 0); 0.0 when there is no cap."""
        return 0.0 if self.limit_usd <= 0 else round(max(0.0, self.limit_usd - self.spent), 6)


def error_analysis(outputs: list[dict], labels: list[dict]) -> dict:
    """Compare case files with labelled alerts; build a failure taxonomy and rank the failure modes.

    Returns {"alerts", "disposition_accuracy", "score_accuracy", "band_accuracy", "escalation_precision",
             "escalation_recall", "taxonomy": {mode: [alert_ids]}, "top_failure_modes": [(mode, count)]}.
    """
    by_id = {o["alert_id"]: o for o in outputs}
    taxonomy: dict[str, list[str]] = {}
    hits = {"disposition": 0, "score": 0, "band": 0}
    tp = fp = fn = 0
    for lab in labels:
        out = by_id.get(lab["alert_id"])
        if out is None:
            taxonomy.setdefault("not_investigated", []).append(lab["alert_id"])
            continue
        aid = lab["alert_id"]
        want_esc = lab["expected_disposition"].startswith("Escalate")
        got_esc = out["recommendation"].startswith("Escalate")
        tp, fp, fn = tp + (want_esc and got_esc), fp + (got_esc and not want_esc), fn + (want_esc and not got_esc)
        if out["recommendation"] == lab["expected_disposition"]:
            hits["disposition"] += 1
        elif want_esc == got_esc:
            taxonomy.setdefault("close_reason_mismatch", []).append(aid)
        else:
            taxonomy.setdefault("missed_escalation" if want_esc else "false_escalation", []).append(aid)
        hits["score"] += out["risk_score"]["score"] == int(lab["expected_risk_score"])
        hits["band"] += out["risk_score"]["band"] == lab["expected_risk_band"]
        want_f = {f.replace("round-tripping", "round_tripping") for f in lab["score_factors"].split(";") if f}
        got_f = {f["factor"] for f in out["risk_score"]["factors"]}
        for f in sorted(want_f - got_f):
            taxonomy.setdefault(f"factor_missed:{f}", []).append(aid)
        for f in sorted(got_f - want_f):
            taxonomy.setdefault(f"factor_extra:{f}", []).append(aid)
        want_t = {x for x in lab["expected_typologies"].split(";") if x and x != "None"}
        got_t = {TYPOLOGY_LABELS.get(t["typology"], t["typology"]) for t in out["typology_assessment"]}
        for t in sorted(want_t - got_t):
            taxonomy.setdefault(f"typology_missed:{t}", []).append(aid)
        for t in sorted(got_t - want_t):
            taxonomy.setdefault(f"typology_extra:{t}", []).append(aid)
    n = len(labels) or 1
    ranked = sorted(((m, len(ids)) for m, ids in taxonomy.items()), key=lambda x: (-x[1], x[0]))
    return {"alerts": len(labels), "disposition_accuracy": round(hits["disposition"] / n, 3),
            "score_accuracy": round(hits["score"] / n, 3), "band_accuracy": round(hits["band"] / n, 3),
            "escalation_precision": round(tp / (tp + fp), 3) if tp + fp else 0.0,
            "escalation_recall": round(tp / (tp + fn), 3) if tp + fn else 0.0,
            "taxonomy": taxonomy, "top_failure_modes": ranked[:3]}


# ----------------------------------------------------------------------------- provided: the traced workflow
def run_investigation(alert_id: str, principal: dict, index, tracer: Tracer, budget: BudgetGuard) -> dict:
    """PROVIDED — one trace for the investigation: the budget is checked BEFORE each agent step, each step is a
    child span, then the Week 2 Supervisor runs. Returns the case file (cost and trace_id attached) or a
    budget_exceeded record."""
    trace_id, root = tracer.start_trace(alert_id)
    spent = 0.0
    for done, (agent, tin, tout, latency) in enumerate(AGENT_TOKEN_PROFILE):
        estimate = round(tin / 1000 * tracer.price_in + tout / 1000 * tracer.price_out, 6)
        if not budget.allow(estimate):
            trace_step(tracer, trace_id, root, agent, 0, 0, 0.0, "budget_exceeded")
            return {"alert_id": alert_id, "status": "budget_exceeded", "steps_completed": done,
                    "cost_usd": round(spent, 6), "trace_id": trace_id}
        span = trace_step(tracer, trace_id, root, agent, tin, tout, latency)
        budget.charge(span["attributes"]["veriguard.cost_usd"])
        spent += span["attributes"]["veriguard.cost_usd"]
    case = investigate(alert_id, principal, index)
    case.update(cost_usd=round(spent, 6), trace_id=trace_id, root_span_id=root)
    return case


def trace_reporting(tracer: Tracer, case: dict, budget: BudgetGuard) -> bool:
    """PROVIDED — add the reporting step to the SAME trace (alert → report); False when the budget refuses it."""
    agent, tin, tout, latency = REPORTING_PROFILE
    estimate = round(tin / 1000 * tracer.price_in + tout / 1000 * tracer.price_out, 6)
    if not budget.allow(estimate):
        trace_step(tracer, case["trace_id"], case["root_span_id"], agent, 0, 0, 0.0, "budget_exceeded")
        return False
    span = trace_step(tracer, case["trace_id"], case["root_span_id"], agent, tin, tout, latency)
    budget.charge(span["attributes"]["veriguard.cost_usd"])
    case["cost_usd"] = round(case.get("cost_usd", 0.0) + span["attributes"]["veriguard.cost_usd"], 6)
    return True
