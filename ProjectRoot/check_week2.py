"""Week 2 self-check — run it after every TODO you finish (PROVIDED, do not modify).

    python check_week2.py              # every task
    python check_week2.py --task 0     # Task 0 only (Azure values in .env)   · --task 1 → tools.py · --task 2 → agents.py
"""
from __future__ import annotations

import os
import sys

os.environ["VERIGUARD_MODE"] = "offline"
os.environ.setdefault("VERIGUARD_LLM", "extractive")
from veriguard.selfcheck import RESULTS, azure_env_check, check, summary  # noqa: E402


def task0() -> None:
    print("\nTask 0 · your Azure values in .env (Weeks 1–2)")
    check("T0", "every Week 1 and Week 2 Azure value is filled in .env, spelled exactly as in the guides",
          lambda: azure_env_check(2))


def task1() -> None:
    print("\nTask 1 · veriguard/tools.py")
    from veriguard import tools

    def typologies():
        r = tools.detect_typologies("ALR-2026-0417")
        names = [t["typology"] for t in r["typologies"]]
        assert names == ["structuring", "layering"], f"ALR-2026-0417 typologies {names}, expected ['structuring', 'layering']"
        assert len(r["typologies"][0]["evidence_txn_ids"]) == 11, "structuring needs the 11 cash-deposit transaction ids as evidence"
        assert tools.detect_typologies("ALR-2026-0452")["typologies"] == [], "ALR-2026-0452 is explained income — no typology"
        return True

    def screening():
        r = tools.screen_customer("CUST-100731")
        assert r["status"] != "no_match", f"CUST-100731 is a name match to a watchlist entity, got {r['status']!r}"
        assert r["differing_identifiers"], "list the differing identifiers (date of birth, nationality) that clear the match"
        assert tools.screen_customer("CUST-100417")["status"] == "no_match", "CUST-100417 has no watchlist match"
        return True

    def scores():
        got = {a: (tools.compute_risk_score(a)["score"], tools.compute_risk_score(a)["band"])
               for a in ("ALR-2026-0417", "ALR-2026-0452", "ALR-2026-0466")}
        want = {"ALR-2026-0417": (80, "High"), "ALR-2026-0452": (0, "Low"), "ALR-2026-0466": (10, "Low")}
        assert got == want, f"score/band {got}, expected {want}"
        facts = [f["factor"] for f in tools.compute_risk_score("ALR-2026-0417")["factors"]]
        assert "typology:structuring" in facts and "hrj_exposure" in facts, f"factors {facts} miss structuring or hrj_exposure"
        return True

    def contract():
        ok = tools.call_tool("detect_typologies", '{"alert_id": "ALR-2026-0417"}')
        assert ok.get("alert_id") == "ALR-2026-0417", "a valid call must return the tool result"
        for bad, why in (("not json", "arguments are not valid JSON"), ('{"alert_id": 5}', "invalid arguments"),
                         ("{}", "invalid arguments")):
            r = tools.call_tool("detect_typologies", bad)
            assert "error" in r and why in r["error"], f"call_tool({bad!r}) → {r}, expected an error containing {why!r}"
        return True

    check("T1.1", "detect_typologies · structuring + layering for ALR-2026-0417, none for ALR-2026-0452", typologies)
    check("T1.2", "screen_customer · name match cleared by two differing identifiers; no match", screening)
    check("T1.3", "compute_risk_score · 80 High / 0 Low / 10 Low with factor evidence", scores)
    check("T1.4", "call_tool · validates arguments and returns {'error': …} instead of raising", contract)


def task2() -> None:
    print("\nTask 2 · veriguard/agents.py")
    from veriguard import agents, tools
    from veriguard.common import dev_principal, make_index
    from veriguard.ingestion import build_corpus
    state: dict = {}

    def ctx():
        if not state:
            index = make_index(build_corpus())
            tools.set_document_index(index)
            agents.reset_state()
            state.update(index=index, inv=dev_principal("Investigator", "EMP-IN-01"),
                         po=dev_principal("PrincipalOfficer", "EMP-PO-01"))
        return state

    def need(alert_id):
        c = agents.CASES.get(alert_id)
        assert c, f"no case file for {alert_id} yet — investigate() and persist_case() must work first (see the ❌ above)"
        return c

    def three_alerts():
        s = ctx()
        want = {"ALR-2026-0417": ("Escalate to Principal Officer", 80), "ALR-2026-0452": ("Close - No Further Action", 0),
                "ALR-2026-0466": ("Close - False Match Cleared", 10)}
        for aid, (rec, score) in want.items():
            c = agents.investigate(aid, s["inv"], s["index"])
            agents.persist_case(c)
            assert (c["recommendation"], c["risk_score"]["score"]) == (rec, score), \
                f"{aid}: got {c['recommendation']!r} / {c['risk_score']['score']}, expected {rec!r} / {score}"
            steps = [x["agent"] for x in c["step_log"]]
            assert steps == ["transaction_monitoring", "risk_assessment", "compliance_investigator"], f"{aid} step_log {steps}"
        return True

    def citations():
        c = need("ALR-2026-0417")
        docs = {r["doc_id"] for r in c["policy_references"]}
        assert docs and docs <= {"DCB-HB-TYP", "DCB-SOP-TMI", "DCB-POL-ESC", "DCB-PRC-SCR", "DCB-MTH-CRR"}, \
            f"policy_references {docs} — cite policy documents only"
        return True

    def hitl():
        c = need("ALR-2026-0417")
        assert c["hitl"] == {"required": True, "decision": "PENDING"} and c["status"] == "Escalated to Principal Officer", \
            f"escalation must wait for the Principal Officer: hitl={c['hitl']} status={c['status']!r}"
        assert need("ALR-2026-0452")["hitl"].get("required") is False, "a Low band close needs no approval"
        return True

    def decide_rules():
        s = ctx()
        try:
            agents.decide("ALR-2026-0417", s["inv"], "approve", "x")
        except PermissionError:
            pass
        else:
            raise AssertionError("an Investigator must not be able to approve")
        r = agents.decide("ALR-2026-0417", s["po"], "approve", "Structuring confirmed")
        assert r["next_step"] == "regulatory_reporting", f"next_step {r.get('next_step')!r}, expected 'regulatory_reporting'"
        try:
            agents.decide("ALR-2026-0417", s["po"], "approve", "again")
        except ValueError:
            return True
        raise AssertionError("a decided case must not accept a second decision (ValueError)")

    def isolation():
        assert "CUST-100417" not in str(need("ALR-2026-0452")), "case memory leaked customer CUST-100417 into another case"
        return True

    check("T2.2", "investigate · the three M2 alerts: disposition, score and the three-step log", three_alerts)
    check("T2.1", "compliance_investigator · cites policy documents only", citations)
    check("T2.2", "investigate · escalation → pending_approval; Low band close needs no approval", hitl)
    check("T2.3", "decide · only the Principal Officer; one decision per case; next step", decide_rules)
    check("T2.2", "case memory · one memory per case, nothing leaks between customers", isolation)


def main() -> int:
    args = sys.argv[1:]
    task = args[args.index("--task") + 1] if "--task" in args else "all"
    print("VeriGuard Week 2 self-check (cumulative: run check_week1.py for Week 1)")
    if task in ("all", "0"):
        task0()
    if task in ("all", "1"):
        task1()
    if task in ("all", "2"):
        task2()
    return summary(2)


if __name__ == "__main__":
    sys.exit(main())
