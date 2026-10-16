"""Week 1 self-check — run it after every TODO you finish (PROVIDED, do not modify).

    python check_week1.py              # every task, including the LLM gateway call
    python check_week1.py --task 1     # Task 1 only (ingestion)   · --task 2 → Task 2 (retrieval) · --task 3 → Task 3 (evaluation + golden set)
    python check_week1.py --task 0     # Task 0 only (.env + LLM gateway)
    python check_week1.py --no-llm     # skip the live gateway call (offline)

Prints one ✅ / ❌ line per check with the reason, then a summary. These are the visible checks; the Evaluate button
runs the full grader, which also checks every document and ranking against frozen expected outcomes and checks your Azure resources live.
"""
from __future__ import annotations

import json
import os
import re
import sys
import traceback
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
os.environ["VERIGUARD_MODE"] = "offline"          # the self-check is always offline (the .env value is ignored here)
sys.path.insert(0, str(ROOT))

from veriguard import common  # noqa: E402

GATEWAY = "https://llmgateway-lms.tekstac.com/v1"
RESULTS: list[tuple[str, bool]] = []


def check(task: str, label: str, fn) -> None:
    try:
        out = fn()
        ok, why = (out, "") if isinstance(out, bool) else (False, str(out))
    except NotImplementedError as exc:
        ok, why = False, f"still a stub ({exc})"
    except AssertionError as exc:
        ok, why = False, str(exc) or "assertion failed"
    except Exception as exc:  # noqa: BLE001 — every failure is reported, never raised
        ok, why = False, f"{type(exc).__name__}: {exc}"
        if os.getenv("VERIGUARD_DEBUG"):
            traceback.print_exc()
    RESULTS.append((task, ok))
    print(f"  {'✅' if ok else '❌'} [{task}] {label}" + ("" if ok else f"\n        → {why}"))


def doc(doc_id: str, version: str):
    m = next(r for r in common.load_manifest() if r["doc_id"] == doc_id and r["version"] == version)
    return m, common.DOCS / m["file"]


def read_env() -> dict:
    path = ROOT / ".env"
    vals = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                vals[k.strip()] = v.strip()
    return vals


# ============================================================================ Task 0 — .env and the LLM gateway
def task0(live: bool) -> None:
    print("\nTask 0 · .env and the LLM gateway")
    env = read_env()

    def env_file():
        assert (ROOT / ".env").exists(), "no .env in the project root — run: cp .env.example .env  (Windows: copy)"
        assert env.get("OPENAI_API_KEY"), "OPENAI_API_KEY is empty in .env — paste the key you were given"
        base = env.get("OPENAI_BASE_URL", GATEWAY).rstrip("/")
        assert base == GATEWAY, f"OPENAI_BASE_URL is {base!r} — it must be {GATEWAY}"
        assert env.get("VERIGUARD_LLM", "gateway") == "gateway", "set VERIGUARD_LLM=gateway in .env"
        return True

    def no_hardcoded_key():
        key = env.get("OPENAI_API_KEY", "")
        bad = []
        for p in ROOT.rglob("*.py"):
            if ".venv" in p.parts or "site-packages" in p.parts:
                continue
            text = p.read_text(encoding="utf-8", errors="ignore")
            if (key and len(key) > 8 and key in text) or re.search(r"\bsk-[A-Za-z0-9_\-]{20,}", text):
                bad.append(str(p.relative_to(ROOT)))
        assert not bad, f"an API key is written in code: {bad} — keep it only in .env"
        return True

    check("T0", ".env has OPENAI_API_KEY, OPENAI_BASE_URL = the gateway, VERIGUARD_LLM=gateway", env_file)
    check("T0", "no API key hard-coded in any .py file", no_hardcoded_key)
    from veriguard.selfcheck import azure_env_check
    check("T0", "every Week 1 Azure value is filled in .env, spelled exactly as in the guide", lambda: azure_env_check(1))
    if live:
        def ping():
            from veriguard import llm
            out = llm.chat([{"role": "user", "content": "Reply with the single word OK."}], max_tokens=5)
            assert out["text"].strip(), "the gateway returned an empty reply"
            return True
        check("T0", "the gateway answers with your key (one tiny call)", ping)


# ============================================================================ Task 1 — ingestion
def task1() -> None:
    print("\nTask 1 · veriguard/ingestion.py")
    from veriguard import ingestion

    def t11_pdf():
        m, p = doc("DCB-POL-KYC", "4.0")
        secs = ingestion.extract_sections(p, m["title"])
        got = [s["section"] for s in secs]
        assert got == ["1", "2", "3", "4", "5", "6", "7"], f"DCB-POL-KYC v4.0 sections {got}, expected 1..7"
        s4 = secs[3]
        assert s4["page"] == 2, f"§4 page {s4['page']!r}, expected 2 (the page the section STARTS on)"
        assert s4["heading"] == "Enhanced Due Diligence for PEPs", f"§4 heading {s4['heading']!r}"
        assert "12 months" in s4["text"], "§4 text should contain '12 months'"
        junk = [s["section"] for s in secs if re.search(r"Page \d|SYNTHETIC TRAINING|Document ID:", s["text"])]
        assert not junk, f"page headers/footers (PAGE_NOISE) left in sections {junk}"
        return True

    def t11_md_headings():
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            syn = Path(tmp) / "DCB-TST-HDR_v1_0.md"
            syn.write_text('---\ndoc_id: DCB-TST-HDR\nversion: "1.0"\n---\n\n# Heading Style Test\n*Deccan Commonwealth Bank - synthetic training data*\n\n## 1. Scope\n\nThe steps are listed below.\n2. Review the alert within one day\nThey are mandatory.\n\n## 2. Escalation\n\nEscalate to the Principal Officer.\n', encoding="utf-8")
            got = [(s["section"], s["heading"]) for s in ingestion.extract_sections(syn, "Heading Style Test")]
        assert got == [("1", "Scope"), ("2", "Escalation")], \
            f"a numbered BODY line started a section: {got} — outside PDFs only '## ' heading lines start one"
        m, p = doc("DCB-SOP-TMI", "3.0")
        secs = ingestion.extract_sections(p, m["title"])
        assert len(secs) == 5, f"DCB-SOP-TMI: {len(secs)} sections, expected 5 (only '## ' heading lines start one)"
        assert all(s["page"] is None for s in secs), "Markdown sections have page None"
        assert secs[4]["heading"] == "Human Approval Requirements" and "70 or above" in secs[4]["text"]
        return True

    def t11_md():
        m, p = doc("DCB-HB-TYP", "2.0")
        secs = ingestion.extract_sections(p, m["title"])
        assert len(secs) == 6, f"DCB-HB-TYP: {len(secs)} sections, expected 6"
        assert not any("doc_id:" in s["text"] or "status:" in s["text"] for s in secs), "front matter in the text"
        return True

    def chunks(doc_id, version):
        m, p = doc(doc_id, version)
        return ingestion.build_chunks(m, ingestion.extract_sections(p, m["title"]))

    def t12_meta():
        for ch in chunks("DCB-POL-KYC", "4.0"):
            for k, v in {"doc_id": "DCB-POL-KYC", "version": "4.0", "status": "current", "classification": "Internal",
                         "doc_type": "policy", "effective_date": "2026-04-01", "source": "DCB-POL-KYC_v4_0.pdf"}.items():
                assert ch.get(k) == v, f"{ch.get('id')}: {k}={ch.get(k)!r}, expected {v!r}"
            assert ch.get("access_roles") == list(common.ROLES), f"access_roles {ch.get('access_roles')!r} — a list"
        return True

    def t12_ids():
        c4 = [c for c in chunks("DCB-POL-KYC", "4.0") if c["section"] == "4"][0]
        assert c4["id"] == "DCB-POL-KYC:4.0:4:0", f"id {c4['id']!r}, expected 'DCB-POL-KYC:4.0:4:0'"
        assert c4["page"] == 2 and c4["chunk_no"] == 0, f"page {c4['page']!r} chunk_no {c4['chunk_no']!r}"
        assert c4["text"].startswith("Enhanced Due Diligence for PEPs. "), "text must start with '<heading>. '"
        return True

    def t12_labels():
        old = chunks("DCB-POL-KYC", "3.2")
        assert old and all(c["status"] == "superseded" and c["superseded_by"] == "4.0" for c in old), \
            "DCB-POL-KYC v3.2 chunks: status 'superseded', superseded_by '4.0'"
        assert all(c["superseded_by"] is None for c in chunks("DCB-POL-KYC", "4.0")), "current: superseded_by None"
        ia = chunks("DCB-IA-2026-06", "Final")
        assert ia and all(c["access_roles"] == ["Auditor"] and c["classification"] == "Board-Restricted" for c in ia), \
            "DCB-IA-2026-06: Board-Restricted, access_roles ['Auditor']"
        return True

    def t12_window():
        m, _ = doc("DCB-POL-KYC", "4.0")
        sec = [{"section": "9", "heading": "Long", "page": 3, "text": " ".join(f"w{i}" for i in range(300))}]
        out = ingestion.build_chunks(m, sec, 120, 20)
        assert [x["chunk_no"] for x in out] == [0, 1, 2], f"300 words → chunk_no 0,1,2, got {[x['chunk_no'] for x in out]}"
        return True

    def t1_corpus():
        all_chunks = ingestion.build_corpus()
        versions = {(c["doc_id"], c["version"]) for c in all_chunks}
        assert len(versions) == 22, f"{len(versions)} document versions, expected 22"
        assert len(all_chunks) == 92, f"{len(all_chunks)} chunks, expected 92"
        return True

    check("T1.1", "extract_sections · PDF: sections 1..7, §4 on page 2, no page furniture", t11_pdf)
    check("T1.1", "extract_sections · Markdown: 5 '## ' sections, page None (DCB-SOP-TMI)", t11_md_headings)
    check("T1.1", "extract_sections · Markdown: 6 sections, front matter removed", t11_md)
    check("T1.2", "build_chunks · manifest metadata on every chunk", t12_meta)
    check("T1.2", "build_chunks · id, page, chunk_no and '<heading>. ' text", t12_ids)
    check("T1.2", "build_chunks · superseded and Board-Restricted labels", t12_labels)
    check("T1.2", "build_chunks · long sections windowed (300 words → 3 chunks)", t12_window)
    check("T1", "build_corpus() → 92 chunks from 22 document versions", t1_corpus)


# ============================================================================ Task 2 — retrieval + golden set
def task2(live: bool, part: str = "all") -> None:
    print("\nTask 2 · veriguard/retrieval.py — security trimming, hybrid search, cited answers" if part in ("all", "2") else "\nTask 3 · evaluate_qa and datapack/04_evaluation/golden_dataset.jsonl")
    from veriguard import ingestion, retrieval
    state: dict = {}

    def index():
        if "index" not in state:
            state["index"] = common.SearchIndex(ingestion.build_corpus())
        return state["index"]

    def t21():
        f = retrieval.is_allowed
        mk = lambda roles, st="current": {"doc_id": "D", "status": st, "access_roles": roles}  # noqa: E731
        internal, conf, board = list(common.ROLES), ["Investigator", "Auditor", "PrincipalOfficer"], ["Auditor"]
        for roles, role, want in ((internal, "Analyst", True), (conf, "Analyst", False), (conf, "Investigator", True),
                                  (board, "PrincipalOfficer", False), (board, "Auditor", True)):
            assert f(mk(roles), role) is want, f"is_allowed(role={role}, access_roles={roles}) should be {want}"
        assert f(mk(internal, "superseded"), "Auditor") is False, "a superseded chunk must never be allowed"
        assert f({"status": "current"}, "Auditor") is False, "missing access_roles must be denied"
        try:
            f(mk(["Analyst"]), "CFO")
        except PermissionError:
            return True
        raise AssertionError("an unknown role ('CFO') must raise PermissionError")

    def t22_shape():
        res = retrieval.hybrid_search(index(), "What is the triage service level for a High priority alert?", "Analyst")
        assert 0 < len(res) <= 5, f"{len(res)} results, expected 1..5"
        need = {"doc_id", "score", "keyword_score", "vector_score", "text"}
        assert all(need <= set(r) for r in res), f"each result needs {sorted(need)}"
        assert all("rerank_score" in r for r in res), "hybrid_rerank results carry rerank_score (from index.rerank)"
        try:
            retrieval.hybrid_search(index(), "x", "Analyst", 5, "bm25")
        except ValueError:
            return True
        raise AssertionError("an unknown mode must raise ValueError")

    def t22_security():
        for q in ("What did Internal Audit find about privileged access in treasury operations?",
                  "What single cash deposit amount triggers an internal monitoring alert at DCB?"):
            for role in ("Analyst", "Investigator", "PrincipalOfficer", "Admin"):
                for mode in retrieval.MODES:
                    for r in retrieval.hybrid_search(index(), q, role, 50, mode):
                        assert r["status"] == "current" and role in r["access_roles"], \
                            f"[{mode}] {role} received {r['doc_id']} v{r['version']} ({r['classification']}/{r['status']})"
        return True

    def t23_superseded():
        r = retrieval.answer_question(index(), "What single cash deposit amount triggers an internal monitoring alert at DCB?",
                                      "Analyst")
        assert not r["refused"], "this question must be answered"
        top = r["citations"][0]
        assert (top["doc_id"], top["version"], top["section"], top["page"]) == ("DCB-POL-KYC", "4.0", "6", 2), \
            f"top citation {top}, expected DCB-POL-KYC v4.0 §6 p.2"
        assert "3,00,000" in r["answer"], "the answer must state Rs 3,00,000"
        assert r["superseded_note"] and "3.2" in r["superseded_note"], "superseded_note must say v3.2 is superseded"
        assert "[DCB-POL-KYC v4.0 §6]" in r["answer"] and "\n\nSources: " in r["answer"], \
            "answer = text + ' [doc v<ver> §<sec>]' (+ Note) + '\\n\\nSources: …'"
        return True

    def t23_declines():
        for q in ("What is DCB's reporting threshold for crypto asset transactions?",
                  "What interest rate does DCB pay on NRE fixed deposits?"):
            r = retrieval.answer_question(index(), q, "Analyst")
            assert r["refused"] and r["answer"] == common.NO_DOCS and r["citations"] == [], f"{q!r} must be declined"
        return True

    def t23_restricted():
        q = "What did Internal Audit find about privileged access in treasury operations?"
        a = retrieval.answer_question(index(), q, "Analyst")
        assert not any(c["doc_id"] == "DCB-IA-2026-06" for c in a["citations"]), "the Analyst received DCB-IA-2026-06"
        b = retrieval.answer_question(index(), q, "Auditor")
        assert any(c["doc_id"] == "DCB-IA-2026-06" for c in b["citations"]), "the Auditor should be answered from it"
        return True

    def t24_metrics():
        import types
        ch = lambda d, v, s, t: {"doc_id": d, "version": v, "section": s, "text": t, "heading": "H"}  # noqa: E731
        idx = types.SimpleNamespace(chunks=[ch("DOC-A", "1", "2", "alpha rule seven days"), ch("DOC-B", "2", "1", "beta")])
        g = lambda q, t, d="", v="", s="": {"qid": q, "question_type": t, "role": "Analyst", "question": q,  # noqa: E731
                                            "expected_doc_ids": d, "expected_versions": v, "expected_sections": s}
        golden = [g("q1", "factual", "DOC-A;DOC-C", "1;1", "2;1"), g("q2", "superseded_trap", "DOC-B", "2", "1"),
                  g("q3", "unanswerable"), g("q4", "unanswerable"), g("q5", "restricted", "DOC-R", "Final", "2")]
        ret = {"q1": ["DOC-X", "DOC-A"], "q2": ["DOC-B"], "q3": ["DOC-Y"], "q4": [], "q5": ["DOC-R", "DOC-Z"]}
        cit = {"q1": [("DOC-A", "1", "2")], "q2": [("DOC-B", "2", "1")], "q3": None, "q4": [("DOC-Y", "1", "1")], "q5": None}

        def fake_answer(index, q, role):
            if cit[q] is None:
                return {"answer": common.NO_DOCS, "citations": [], "sources": [], "refused": True, "superseded_note": None}
            return {"answer": "alpha rule seven days\n\nSources: x", "refused": False, "sources": ["x"],
                    "citations": [{"doc_id": d, "version": v, "section": s, "page": None} for d, v, s in cit[q]],
                    "superseded_note": "DOC-B v1 is superseded by v2" if q == "q2" else None}
        saved = retrieval.hybrid_search, retrieval.answer_question
        retrieval.hybrid_search = lambda index, q, role, k=5, mode="hybrid_rerank": [{"doc_id": d} for d in ret[q]]
        retrieval.answer_question = fake_answer
        try:
            r = retrieval.evaluate_qa(idx, golden, 5)
        finally:
            retrieval.hybrid_search, retrieval.answer_question = saved
        want = {"recall_at_k": 0.75, "citation_accuracy": 1.0, "decline_rate": 0.5, "superseded_accuracy": 1.0, "leaks": 1}
        got = {k: r.get(k) for k in want}
        assert all(abs((got[k] or 0) - v) < 1e-6 for k, v in want.items()), f"on the 5-item example expected {want}, got {got}"
        assert {i["qid"] for i in r["items"]} == {"q1", "q2", "q3", "q4", "q5"}, "one item per question"
        return True

    def t24_bar():
        r = retrieval.evaluate_qa(index(), common.load_golden(), 5)
        keys = ("recall_at_k", "citation_accuracy", "decline_rate", "superseded_accuracy", "groundedness", "leaks")
        ok = (r["recall_at_k"] >= .8 and r["citation_accuracy"] >= .9 and r["decline_rate"] >= .8
              and r["superseded_accuracy"] == 1.0 and r["groundedness"] >= 4.0 and r["leaks"] == 0)
        print("        " + " · ".join(f"{k} {r[k]}" for k in keys))
        assert ok, "M1 bar not met on your golden set (Recall ≥ 0.80, citation ≥ 0.90, decline ≥ 0.80, superseded 1.0, " \
                   "groundedness ≥ 4.0, leaks 0) — if only decline_rate is short, author more unanswerable questions"
        return True

    def t25():
        rows = common.load_golden()
        seed = {f"GQ-{i:03d}" for i in range(1, 31)}
        assert seed <= {x["qid"] for x in rows}, "keep the 30 seeded questions GQ-001 … GQ-030"
        new = [x for x in rows if x["qid"] not in seed]
        kinds = Counter(x["question_type"] for x in new)
        assert len(new) >= 10, f"{len(new)} questions added, need ≥ 10"
        assert kinds["unanswerable"] >= 3 and kinds["superseded_trap"] >= 3, \
            f"your additions {dict(kinds)} — need ≥ 3 unanswerable and ≥ 3 superseded_trap"
        keys = {"qid", "question_type", "role", "question", "reference_answer", "expected_doc_ids", "expected_versions",
                "expected_sections"}
        current = {(m["doc_id"], m["version"]) for m in common.load_manifest() if m["status"].lower() == "current"}
        for x in new:
            assert keys <= set(x), f"{x.get('qid')}: missing {sorted(keys - set(x))}"
            assert x["role"] in common.ROLES, f"{x['qid']}: unknown role {x['role']!r}"
            for d, v, _ in common.expected_citations(x):
                assert (d, v) in current, f"{x['qid']}: {d} v{v} is not a CURRENT document version"
        return True

    with common.llm_provider("extractive"):        # deterministic, like the grader
        if part in ("all", "2"):
            check("T2.1", "is_allowed · role grid, superseded denied, unknown role → PermissionError", t21)
            check("T2.2", "hybrid_search · scored result dicts, rerank_score, bad mode → ValueError", t22_shape)
            check("T2.2", "hybrid_search · never returns superseded / unauthorised chunks (all modes, k=50)", t22_security)
            check("T2.3", "answer_question · superseded trap → Rs 3,00,000 from DCB-POL-KYC v4.0 §6 p.2 + note", t23_superseded)
            check("T2.3", "answer_question · unanswerable questions declined with NO_DOCS", t23_declines)
            check("T2.3", "answer_question · Board-Restricted audit: Analyst trimmed, Auditor answered", t23_restricted)
        if part in ("all", "3"):
            if part == "all":
                print("\nTask 3 · evaluate_qa and datapack/04_evaluation/golden_dataset.jsonl")
            check("T3.1", "evaluate_qa · metric definitions on a 5-item example", t24_metrics)
            check("T3.2", "golden set · ≥ 10 added, ≥ 3 unanswerable, ≥ 3 superseded traps, valid fields", t25)
            check("T3.1", "evaluate_qa · M1 bar met on your golden set (hybrid_rerank)", t24_bar)
    if part in ("all", "2") and live and common.LLM_PROVIDER == "gateway":
        def t23_gateway():
            from veriguard import llm
            with common.llm_provider("gateway"):
                r = retrieval.answer_question(index(), "How often must PEP relationships be reviewed?", "Analyst")
            assert llm.LAST["ok"], f"gateway call failed ({llm.LAST['kind']}): {llm.LAST['error']}"
            assert r["citations"] and r["citations"][0]["doc_id"] == "DCB-POL-KYC", "citations must not change"
            print("        " + r["answer"].split("\n")[0][:160])
            return True
        check("T2.3", "answer_question · answer text written by the LLM gateway, citations unchanged", t23_gateway)


def main() -> int:
    args = sys.argv[1:]
    task = args[args.index("--task") + 1] if "--task" in args else "all"
    live = "--no-llm" not in args
    print(f"VeriGuard Week 1 self-check · project {ROOT}")
    print(f"LLM provider: {common.LLM_PROVIDER}" + ("" if live else " (gateway call skipped: --no-llm)"))
    if task in ("all", "0"):
        task0(live)
    if task in ("all", "1"):
        task1()
    if task in ("all", "2", "3"):
        task2(live, task)
    passed = sum(ok for _, ok in RESULTS)
    print(f"\nWeek 1 self-check: {passed}/{len(RESULTS)} checks passing"
          + (" — all green ✅  (now click Evaluate)" if passed == len(RESULTS) else " — fix the ❌ lines above"))
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
