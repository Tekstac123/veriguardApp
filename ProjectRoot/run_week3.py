"""Week 3 demo — M3 Secure & Governed (PROVIDED, do not modify).   python run_week3.py

Signs in from token claims, runs the CISO's three findings, the red-team (datapack/05_security/attack_set.jsonl), the
20 cross-role access tests, the 20 PII tests, verifies the audit chain and runs the CI quality gate.
"""
from __future__ import annotations

from veriguard.common import LIVE, SECURITY, load_golden, load_json, load_jsonl, make_index, write_report
from veriguard.ingestion import build_corpus


def main() -> None:
    import sys
    if "--azure-check" in sys.argv:
        from veriguard import livecheck
        raise SystemExit(livecheck.main(3))
    try:
        from veriguard.governance import (AuditLog, pii_in_audit, quality_gate, run_access_tests, run_pii_tests,
                                          run_redteam, secure_ask, verify_chain)
        from veriguard.retrieval import evaluate_qa
        from veriguard.security import principal_from_claims
        tokens = load_json(SECURITY / "tokens.json")
        now = tokens["_now"]
        for name in ("forged_tenant", "forged_audience", "expired", "no_known_group"):
            try:
                principal_from_claims(tokens[name], now)
                print(f"token {name}: ACCEPTED ✘")
            except PermissionError as exc:
                print(f"token {name}: rejected — {exc}")
        index, audit = make_index(build_corpus()), AuditLog()
        analyst = principal_from_claims(tokens["analyst"], now)
        for q in ("What did Internal Audit find about privileged access in treasury operations?",
                  "Customer Aadhaar 6343 6745 4641 deposited cash. What single cash deposit amount triggers an alert?",
                  "Summarise the Northwind Data Services vendor onboarding note."):
            r = secure_ask(index, q, analyst, audit)
            print(f"\n[Analyst] {q}\n  → {r['answer'][:220]}\n  flags {r['flags']}")
        red, access, pii = run_redteam(index, audit=audit), run_access_tests(index, audit), run_pii_tests()
        print(f"\nRed-team {red['handled']}/{red['attacks']} ({red['handled_rate']:.0%}) · open critical {red['open_critical']}")
        print(f"Access tests {access['passed']}/{access['tests']} · unauthorised {access['unauthorized_access']}")
        print(f"PII tests {pii['passed']}/20 · raw PII in the audit log: {pii_in_audit(audit)}")
        print("Audit chain:", verify_chain(audit.entries()), f"over {len(audit.entries())} entries")
        if LIVE:
            from veriguard import azure
            tests = load_jsonl(SECURITY / "pii_test_set.jsonl")
            found = sum(1 for t in tests if t["expected_masks"] and azure.pii_entities(t["text"]))
            print(f"LIVE · Azure AI Language PII second opinion: entities found in {found}/"
                  f"{sum(1 for t in tests if t['expected_masks'])} PII tests · audit entries in the immutable audit-log "
                  f"container · Prompt Shields screened every prompt and retrieved document")
        m1 = evaluate_qa(index, load_golden())
        metrics = {**{k: m1[k] for k in ("recall_at_k", "citation_accuracy", "decline_rate", "groundedness",
                                         "superseded_accuracy", "leaks")},
                   "attack_handled_rate": red["handled_rate"], "pii_leaks": pii["pii_leaks"] + pii_in_audit(audit),
                   "unauthorized_access": access["unauthorized_access"]}
        print("CI gate (this build):", quality_gate(metrics, baseline=metrics))
        regressed = {**metrics, "citation_accuracy": round(metrics["citation_accuracy"] - 0.05, 3)}
        print("CI gate (a PR that regresses citation accuracy):", quality_gate(regressed, baseline=metrics))
        write_report({"metrics": metrics, "redteam": red, "access": access, "pii": pii}, "week3_m3_evidence.json")
    except NotImplementedError as exc:
        print(f"Not finished yet: {exc}")


if __name__ == "__main__":
    main()
