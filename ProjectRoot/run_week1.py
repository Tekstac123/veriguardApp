"""Week 1 demo — L0/M1 Grounded Financial Intelligence (PROVIDED, do not modify).

    python run_week1.py               # demo answers by the LLM gateway + M1 evaluation (deterministic answers)
    python run_week1.py --llm-eval    # the M1 evaluation ALSO uses gateway answers (≈150 model calls, slower)
    python run_week1.py --push-index  # (after Task 1) upload YOUR chunks + embeddings into the Azure AI Search index
    python run_week1.py --sync        # download the corpus from Blob Storage with your identity (live mode reads it)
    python run_week1.py --azure-check # sign-in, models, containers and index — what the Azure steps of the problem statement created

Builds the index from the 22 documents, answers the Week 1 questions as each role (answer text written by the LLM
gateway when OPENAI_API_KEY is in .env), runs the evaluation and the ablation (vector vs hybrid vs hybrid + rerank) on
datapack/04_evaluation/golden_dataset.jsonl, and writes reports/week1_m1_evaluation.json.

The M1 metrics are measured on extractive answers by default — exactly what the evaluator grades — so the numbers are
reproducible; retrieval, citations, declines and leaks are identical either way.
"""
from __future__ import annotations

import os
import sys
from collections import Counter
from contextlib import nullcontext

from veriguard import common
from veriguard.common import LIVE, load_golden, make_index, write_report
from veriguard.ingestion import build_corpus

QUESTIONS = [("Analyst", "What single cash deposit amount triggers an internal monitoring alert at DCB?"),
             ("Analyst", "How often must PEP relationships be reviewed?"),
             ("Investigator", "What is the deadline for filing an STR?"),
             ("Analyst", "What did Internal Audit find about privileged access in treasury operations?"),
             ("Auditor", "What did Internal Audit find about privileged access in treasury operations?"),
             ("Analyst", "What is DCB's reporting threshold for crypto asset transactions?")]


def describe_llm() -> str:
    provider = common.LLM_PROVIDER
    if provider == "gateway":
        from veriguard import llm
        s = llm.settings()
        if not s["key_set"]:
            return "answers: extractive (VERIGUARD_LLM=gateway but OPENAI_API_KEY is not set in .env)"
        return f"answers by {s['model']} via the LLM gateway {s['base_url']}"
    if provider == "azure" and LIVE:
        return f"answers by {os.getenv('AZURE_AI_MODEL_DEPLOYMENT_NAME', 'gpt-4.1-mini')} on your Foundry resource"
    return "answers: extractive (no model call — set OPENAI_API_KEY and VERIGUARD_LLM=gateway in .env)"


def main() -> None:
    if "--azure-check" in sys.argv:
        from veriguard import livecheck
        raise SystemExit(livecheck.main(1))
    if "--sync" in sys.argv:
        from veriguard import sync
        return sync.main()
    llm_eval = "--llm-eval" in sys.argv
    try:
        chunks = build_corpus()
    except NotImplementedError as exc:
        print(f"Task 1 not finished yet: {exc}")
        return
    print(f"Indexed {len(chunks)} chunks from {len({(c['doc_id'], c['version']) for c in chunks})} document versions · "
          + ", ".join(f"{k}={v}" for k, v in Counter(c.get("classification") for c in chunks).most_common()))
    if "--push-index" in sys.argv:
        from veriguard import azure
        res = azure.push_index(chunks)
        print(f"Index {res['index']}: {res['uploaded']} chunks uploaded ✅ — open it in the portal: Search explorer")
        return
    index = make_index(chunks)
    if LIVE:
        print(f"LIVE · Azure AI Search index {os.getenv('AZURE_SEARCH_INDEX', 'veriguard-m1')} · corpus synced from "
              f"Blob Storage")
    print(f"LLM · {describe_llm()}")
    try:
        from veriguard.retrieval import answer_question, evaluate_qa
        for role, q in QUESTIONS:
            print(f"\n[{role}] {q}\n  " + answer_question(index, q, role)["answer"].replace("\n", "\n  "))
        if common.LLM_PROVIDER == "gateway":
            from veriguard import llm
            last = llm.LAST
            print(f"\nLLM gateway last call: {'OK' if last['ok'] else 'FAILED (' + str(last['kind']) + ')'} · model "
                  f"{last['model']} · {last['input_tokens']} in / {last['output_tokens']} out tokens"
                  + (f"\n  {last['error']}" if last.get("error") else ""))
        golden = load_golden()
        scope = nullcontext() if llm_eval else common.llm_provider("extractive")
        with scope:
            report = {m: evaluate_qa(index, golden, 5, m) for m in ("vector", "hybrid", "hybrid_rerank")}
    except NotImplementedError as exc:
        print(f"\nTask 2 not finished yet: {exc}")
        return
    print(f"\nGolden set: {len(golden)} questions · metrics on "
          + ("LLM gateway answers" if llm_eval else "extractive answers (deterministic, as graded)"))
    for mode, r in report.items():
        print(f"  [{mode:<13}] Recall@5 {r['recall_at_k']:.3f} · citation {r['citation_accuracy']:.3f} · decline "
              f"{r['decline_rate']:.3f} · superseded {r['superseded_accuracy']:.3f} · grounded {r['groundedness']:.2f} · "
              f"leaks {r['leaks']}")
    print("M1 bar: Recall@5 ≥ 0.80 · citation ≥ 0.90 · decline ≥ 0.80 · superseded 1.0 · groundedness ≥ 4.0 · leaks 0")
    r = report["hybrid_rerank"]
    met = (r["recall_at_k"] >= .8 and r["citation_accuracy"] >= .9 and r["decline_rate"] >= .8
           and r["superseded_accuracy"] == 1.0 and r["groundedness"] >= 4.0 and r["leaks"] == 0)
    print("M1 bar (hybrid_rerank): " + ("MET ✅" if met else "NOT MET ❌"))
    print("Report →", write_report(report, "week1_m1_evaluation.json").name)
    if LIVE:
        print("LIVE · note the golden-set size you measured in your Week 1 document")


if __name__ == "__main__":
    main()
