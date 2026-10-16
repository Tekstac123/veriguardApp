"""Week 1 · Task 2 — Security-trimmed hybrid retrieval, grounded answers with citations, and the M1 evaluation.

Only current documents the user's role may see are ever ranked; every answer cites document, version, section and
page, says so when a superseded version exists, and declines when the evidence is insufficient. The answer TEXT is
written by the LLM gateway (compose_answer → veriguard/llm.py, key from .env); the citations come from your code.

Find your work with:  grep -n "TODO" veriguard/retrieval.py
Check it with:        python check_week1.py --task 2   (evaluate_qa: --task 3)
"""
from __future__ import annotations

from .common import (  # noqa: F401 — helpers you will need
    MIN_COVERAGE, MIN_SIMILARITY, NO_DOCS, ROLES, RRF_K, SearchIndex, citation_of, compose_answer,
    expected_citations, groundedness, source_line, superseded_versions)

# ─── WEEK 1 · L0 + M1 Grounded Financial Intelligence — you implement the stubbed functions in this file in Week 1 ───

MODES = ("vector", "hybrid", "hybrid_rerank")
RERANK_CANDIDATES = 50


def is_allowed(chunk: dict, role: str) -> bool:
    """Security trimming: the chunk is current AND the role is in its access_roles. Unknown role → PermissionError."""
    if role not in ROLES:
        raise PermissionError(f"unknown role {role!r}")
    return chunk.get("status") == "current" and role in (chunk.get("access_roles") or [])


def hybrid_search(index: SearchIndex, query: str, role: str, k: int = 5, mode: str = "hybrid_rerank") -> list[dict]:
    """Top-k allowed chunks: 'vector' ranking only, 'hybrid' (RRF of BM25 + vector) or 'hybrid_rerank' (+ rerank).

    Results are copies of the chunks plus 'score', 'keyword_score', 'vector_score' (+ 'rerank_score').
    """
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
    kw, vec = index.keyword_scores(query), index.vector_scores(query)
    allowed = [i for i, c in enumerate(index.chunks) if is_allowed(c, role)]
    rankings = [sorted((i for i in allowed if vec[i] >= MIN_SIMILARITY), key=lambda i: (-vec[i], i))]
    if mode != "vector":
        rankings.append(sorted((i for i in allowed if kw[i] > 0), key=lambda i: (-kw[i], i)))
    fused: dict[int, float] = {}
    for ranking in rankings:
        for rank, i in enumerate(ranking, start=1):
            fused[i] = fused.get(i, 0.0) + 1.0 / (RRF_K + rank)
    order = sorted(fused, key=lambda i: (-fused[i], i))
    results = [{**index.chunks[i], "score": round(fused[i], 6), "keyword_score": kw[i], "vector_score": vec[i]}
               for i in order[:RERANK_CANDIDATES if mode == "hybrid_rerank" else k]]
    if mode == "hybrid_rerank":
        results = index.rerank(query, results)
    return results[:k]


def answer_question(index: SearchIndex, question: str, role: str) -> dict:
    """Grounded answer citing the two best sections, with a superseded-version note — or the NO_DOCS decline.

    Returns {"answer", "citations": [{"doc_id", "version", "section", "page"}], "sources", "refused",
    "superseded_note"}.
    """
    results = hybrid_search(index, question, role, k=5, mode="hybrid_rerank")
    if not results or max(index.coverage(question, r) for r in results) < MIN_COVERAGE:
        return {"answer": NO_DOCS, "citations": [], "sources": [], "refused": True, "superseded_note": None}
    cited = [results[0]] + [r for r in results[1:2] if index.coverage(question, r) >= MIN_COVERAGE]
    top = cited[0]
    notes = []
    for doc_id in dict.fromkeys(c["doc_id"] for c in cited):
        current = next(c["version"] for c in cited if c["doc_id"] == doc_id)
        for old in superseded_versions(doc_id):
            notes.append(f"{doc_id} v{old['version']} is superseded by v{current}; this answer uses v{current}.")
    note = " ".join(notes) or None
    answer = f"{compose_answer(question, cited)} [{top['doc_id']} v{top['version']} §{top['section']}]"
    if note:
        answer += f"\nNote: {note}"
    answer += "\n\nSources: " + "; ".join(source_line(c) for c in cited)
    return {"answer": answer, "citations": [citation_of(c) for c in cited], "sources": [source_line(c) for c in cited],
            "refused": False, "superseded_note": note}


def evaluate_qa(index: SearchIndex, golden: list[dict], k: int = 5, mode: str = "hybrid_rerank") -> dict:
    """M1 metrics: Recall@k and citation accuracy (answerable items), decline rate (unanswerable), superseded-trap
    accuracy, groundedness (answered items) and leaks (restricted items). Returns the metrics plus "items"."""
    rows, leaks = [], 0
    for item in golden:
        role, kind = item["role"], item["question_type"]
        expected = expected_citations(item)
        hits = hybrid_search(index, item["question"], role, k=4 * k, mode=mode)
        retrieved = list(dict.fromkeys(h["doc_id"] for h in hits))[:k]
        ans = answer_question(index, item["question"], role)
        row = {"qid": item["qid"], "type": kind, "role": role, "retrieved": retrieved, "refused": ans["refused"],
               "citations": ans["citations"]}
        if kind == "unanswerable":
            row["declined"] = ans["refused"]
        elif kind == "restricted":     # safe = nothing from the restricted target is retrieved or cited
            targets = {e[0] for e in expected}
            row["leaked"] = sorted({d for d in retrieved if d in targets} | {c["doc_id"] for c in ans["citations"]
                                                                            if c["doc_id"] in targets})
            leaks += len(row["leaked"])
        else:
            docs = {e[0] for e in expected}
            row["recall"] = len(docs & set(retrieved)) / len(docs) if docs else 0.0
            row["citation_ok"] = (not ans["refused"]) and any(
                (c["doc_id"], c["version"], c["section"]) in expected for c in ans["citations"])
            if not ans["refused"]:
                cited = [h for h in index.chunks if any(h["doc_id"] == c["doc_id"] and h["version"] == c["version"]
                                                        and h["section"] == c["section"] for c in ans["citations"])]
                row["groundedness"] = groundedness(ans["answer"], cited)
            if kind == "superseded_trap":
                row["superseded_ok"] = row["citation_ok"] and bool(ans["superseded_note"])
        rows.append(row)

    def mean(key, subset):
        vals = [r[key] for r in subset if key in r]
        return round(sum(vals) / len(vals), 3) if vals else 0.0
    return {"k": k, "mode": mode, "recall_at_k": mean("recall", rows), "citation_accuracy": mean("citation_ok", rows),
            "decline_rate": mean("declined", rows), "superseded_accuracy": mean("superseded_ok", rows),
            "groundedness": mean("groundedness", rows), "leaks": leaks, "items": rows}
