"""VeriGuard shared helpers — PROVIDED, do not modify.

Plumbing every week builds on, over the official VeriGuard Learner Data Pack (datapack/): document readers for the PDF
and Markdown corpus, the corpus manifest, an offline search index (BM25 + embeddings + synonym map + semantic
reranker stand-ins for Azure AI Search), read-only access to the core-banking database (dcb_core.sql, built into SQLite on first use), the risk
methodology points, masking, schema validation, identity and audit helpers. Retrieval runs offline — no Azure needed. Answers are
written by the LLM gateway (OPENAI_API_KEY in .env, see veriguard/llm.py) when VERIGUARD_LLM=gateway.
Each stand-in is named after the Azure feature it imitates so the habits carry over to the cloud build.
"""
from __future__ import annotations

import csv
import datetime as _dt
import hashlib
import json
import math
import re
import sqlite3
import tempfile
from collections import Counter
from contextlib import contextmanager
from difflib import SequenceMatcher
from pathlib import Path

import os  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader (KEY=value lines; comments on their own line). Existing variables win."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())


_load_dotenv(ROOT / ".env")
MODE = os.getenv("VERIGUARD_MODE", "offline").strip().lower()   # "offline" (default, graded) or "live" (Azure)
LIVE = MODE == "live"
# Who writes the answer text for the sections answer_question cites (retrieval and citations never change):
#   gateway    → the course LLM gateway (OPENAI_API_KEY, OPENAI_BASE_URL, OPENAI_CHAT_MODEL in .env)  [default with a key]
#   azure      → gpt-4.1-mini on YOUR Foundry resource (live mode only)
#   extractive → the best sentences of the top section — deterministic; what the metrics are graded on
LLM_PROVIDER = (os.getenv("VERIGUARD_LLM") or ("gateway" if os.getenv("OPENAI_API_KEY", "").strip()
                                               else "azure" if LIVE else "extractive")).strip().lower()
AZURE_CACHE = ROOT / ".azure_cache"                               # veriguard/sync.py downloads here
DATA = ROOT / "datapack"                                           # the official VeriGuard Learner Data Pack
DOCS = AZURE_CACHE / "01_documents" if LIVE and (AZURE_CACHE / "01_documents").exists() else DATA / "01_documents"
STRUCTURED = (AZURE_CACHE / "02_structured_data" if LIVE and (AZURE_CACHE / "02_structured_data" / "dcb_core.sql").exists()
              else DATA / "02_structured_data")
ALERTS = DATA / "03_alerts"
EVALUATION = DATA / "04_evaluation"
SECURITY = DATA / "05_security"
TEMPLATES = DATA / "06_templates"
REPORTS = ROOT / "reports"

ROLES = ("Analyst", "Investigator", "Auditor", "PrincipalOfficer", "Admin")
NO_DOCS = "I can't find this in DCB's approved documents that you are allowed to see, so I won't guess."


def load_json(path: Path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def load_csv(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8-sig") as fh:
        return [dict(r) for r in csv.DictReader(fh)]


def write_report(report: dict, name: str) -> Path:
    REPORTS.mkdir(parents=True, exist_ok=True)
    path = REPORTS / name
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    return path


def now_iso() -> str:
    return _dt.datetime.now().replace(microsecond=0).isoformat()


# ============================================================================= Week 1 — documents and the manifest
def load_manifest() -> list[dict]:
    """datapack/01_documents/corpus_manifest.csv — the source of truth for version, status, classification and the
    roles allowed to see each document. One row per document *version* (superseded versions included)."""
    return load_csv(DOCS / "corpus_manifest.csv")


DOC_TYPES = {"POL": "policy", "STD": "standard", "SOP": "procedure", "PRC": "procedure", "HB": "handbook",
             "MTH": "methodology", "REG": "register", "RD": "regulatory_digest", "IA": "audit_report",
             "CC": "circular", "VND": "vendor_note"}


def doc_type_of(doc_id: str) -> str:
    """'DCB-POL-KYC' → 'policy', 'DCB-IA-2026-03' → 'audit_report' (the second part of the document id)."""
    parts = doc_id.split("-")
    return DOC_TYPES.get(parts[1] if len(parts) > 1 else "", "other")


def superseded_versions(doc_id: str) -> list[dict]:
    """Manifest rows of the superseded versions of doc_id (e.g. DCB-POL-KYC v3.2), oldest first."""
    rows = [r for r in load_manifest() if r["doc_id"] == doc_id and r["status"].lower() == "superseded"]
    return sorted(rows, key=lambda r: r["effective_date"])


SECTION_HEADING = re.compile(r"^(?P<section>\d{1,2})\.\s+(?P<heading>[A-Z][^\n]{2,80})$")
PAGE_NOISE = re.compile(r"^(Deccan Commonwealth Bank( - .*)?|Page \d+|SYNTHETIC TRAINING DATA - FICTIONAL ENTITY|"
                        r"Document ID:.*|Effective date:.*|Classification:.*|\*Deccan Commonwealth Bank.*\*|# .*)$")


def document_lines(path: Path) -> list[tuple[int | None, str, bool]]:
    """Every non-empty line of a corpus document as (page, text, is_heading_style).

    PDF  → page numbers 1, 2, …; is_heading_style is False (PDF headings are plain lines like '4. Enhanced Due …')
    MD   → page None; front matter removed; is_heading_style True for '## …' lines (the '## ' is stripped)
    The corpus is PDF and Markdown only — Word (.doc / .docx) files are not supported and raise ValueError.
    Page headers/footers and the title block are still in the output — remove them with PAGE_NOISE.
    """
    path = Path(path)
    out: list[tuple[int | None, str, bool]] = []
    if path.suffix == ".pdf":
        from pypdf import PdfReader
        for number, page in enumerate(PdfReader(str(path)).pages, start=1):
            out += [(number, line.strip(), False) for line in (page.extract_text() or "").splitlines() if line.strip()]
    elif path.suffix.lower() == ".md":
        text = path.read_text(encoding="utf-8")
        if text.startswith("---"):
            text = text.split("---", 2)[2]
        for line in text.splitlines():
            line = line.strip()
            if line:
                out.append((None, line[3:].strip() if line.startswith("## ") else line, line.startswith("## ")))
    else:
        raise ValueError(f"{path.name}: unsupported document type {path.suffix!r} — the corpus is PDF and Markdown only")
    return out


def split_words(text: str, max_words: int = 120, overlap: int = 20) -> list[str]:
    """Sliding word window: pieces of at most max_words, each sharing `overlap` words with the previous one."""
    if overlap >= max_words:
        raise ValueError("overlap must be smaller than max_words")
    words = text.split()
    if len(words) <= max_words:
        return [" ".join(words)] if words else []
    pieces, start = [], 0
    while start < len(words):
        pieces.append(" ".join(words[start:start + max_words]))
        if start + max_words >= len(words):
            break
        start += max_words - overlap
    return pieces


# ----------------------------------------------------------------------------- text analysis (the index's analyzer)
STOP = set("a an the is are am i my me you your we our to of for in on at and or if it its this that be can do does "
           "what how much with by as from will would should could have has please tell about there their they so any "
           "up out get which who whom when where dcb s per under must shall may being been into than then also within "
           "after before over does".split())
ACRONYMS = {"pep": "politically exposed person", "str": "suspicious transaction report", "ctr": "cash transaction report",
            "kyc": "know your customer", "edd": "enhanced due diligence", "cdd": "customer due diligence",
            "hrj": "high risk jurisdiction", "fiu": "financial intelligence unit", "aml": "anti money laundering",
            "dpdp": "digital personal data protection", "upi": "unified payments interface"}
SYNONYM_MAP = [   # Azure AI Search 'synonym map' stand-in: each group indexes as its first stem
    ("automat", "autonom"), ("sharehold", "share"), ("threshold", "limit"), ("display", "mask", "shown"),
    ("approv", "authoris", "sign"), ("retain", "retention", "kept", "keep"), ("deadline", "timeline", "later"),
    ("flag", "generat")]


def _stem(t: str) -> str:
    for suf in ("ations", "ation", "ings", "ing", "ied", "ies", "ed", "es", "s", "al", "ly"):
        if t.endswith(suf) and len(t) > len(suf) + (2 if suf == "s" else 3):
            return t[:-len(suf)]
    return t


def tokenize(text: str) -> list[str]:
    """Lower-case stemmed tokens without stop words; acronyms expanded; synonym-map groups added."""
    out: list[str] = []
    for t in re.findall(r"[a-z0-9]+", (text or "").lower()):
        if t in STOP or len(t) < 2:
            continue
        stem = _stem(t)
        out.append(stem)
        if stem in ACRONYMS:
            out += [_stem(x) for x in ACRONYMS[stem].split()]
    extra = [grp[0] for t in out for grp in SYNONYM_MAP if any(t.startswith(g) for g in grp)]
    return out + extra


def embed(text: str, dim: int = 384) -> list[float]:
    """Offline embedding model (hashed unigrams + bigrams over the analyzer's tokens). Deterministic."""
    vec = [0.0] * dim
    toks = tokenize(text)
    for g in toks + [f"{a}_{b}" for a, b in zip(toks, toks[1:])]:
        h = int(hashlib.md5(g.encode()).hexdigest(), 16)
        vec[h % dim] += 1.0 if (h >> 9) % 2 else -1.0
    return vec


def cosine(a: list[float], b: list[float]) -> float:
    na, nb = math.sqrt(sum(x * x for x in a)), math.sqrt(sum(x * x for x in b))
    return 0.0 if not na or not nb else sum(x * y for x, y in zip(a, b)) / (na * nb)


def best_sentences(text: str, query: str, n: int = 2) -> str:
    """The n sentences of `text` that share most tokens with `query`, in their original order."""
    sentences = [s for s in re.split(r"(?<=[.!?])\s+", text or "") if s.strip()]
    q = set(tokenize(query))
    ranked = sorted(range(len(sentences)), key=lambda i: (-len(q & set(tokenize(sentences[i]))), i))[:n]
    return " ".join(sentences[i] for i in sorted(ranked))


def compose_answer(question: str, chunks: list[dict]) -> str:
    """The answer text for the cited chunks (best first), written by LLM_PROVIDER:
    gateway → the LLM gateway model writes a grounded answer from these chunks only (veriguard/llm.py);
    azure (live) → gpt-4.1-mini on your Foundry resource; extractive → the best sentences of the top chunk.
    If the model declines, the content filter blocks it or the call fails, the extractive answer is used."""
    if LLM_PROVIDER == "gateway":
        from . import llm
        text = llm.grounded_answer(question, chunks) if llm.configured() else ""
        if text:
            return text
    elif LLM_PROVIDER == "azure" and LIVE:
        from . import azure
        text = azure.grounded_answer(question, chunks)
        if text:
            return text
    return best_sentences(chunks[0]["text"], question)


@contextmanager
def llm_provider(name: str):
    """Temporarily switch who writes answers, e.g. `with llm_provider("extractive"): evaluate_qa(...)`."""
    global LLM_PROVIDER
    saved, LLM_PROVIDER = LLM_PROVIDER, name
    try:
        yield
    finally:
        LLM_PROVIDER = saved


RRF_K = 60                 # Reciprocal Rank Fusion constant (what Azure AI Search uses)
MIN_SIMILARITY = 0.20      # vector hits below this cosine are noise and are not candidates
MIN_COVERAGE = 0.45        # the evidence must cover this share of the question (IDF-weighted) — otherwise decline
HEADING_WEIGHT = 0.5       # semantic configuration: the section heading is a prioritised field


class SearchIndex:
    """In-memory search index over chunk dicts — VeriGuard's stand-in for Azure AI Search.

    index.chunks                 the chunk dicts, in the order given
    index.keyword_scores(q)      BM25 score per chunk (0 = no match)
    index.vector_scores(q)       cosine similarity per chunk (embed())
    index.coverage(q, chunk)     IDF-weighted share of the query's tokens found in the chunk (0.0–1.0)
    index.rerank(q, results)     semantic-ranker stand-in: coverage + HEADING_WEIGHT × heading coverage, best first
    """

    def __init__(self, chunks: list[dict]):
        self.chunks = list(chunks)
        texts = [f"{c.get('title', '')}. {c.get('heading', '')}. {c.get('text', '')}" for c in self.chunks]
        self._tf = [Counter(tokenize(t)) for t in texts]
        self._sets = [set(tf) for tf in self._tf]
        self._df = Counter(t for s in self._sets for t in s)
        self._avg = sum(sum(tf.values()) for tf in self._tf) / max(1, len(self._tf))
        self._vectors = [embed(t) for t in texts]

    def __len__(self) -> int:
        return len(self.chunks)

    def idf(self, token: str) -> float:
        n = len(self.chunks) or 1
        return math.log(1 + (n - self._df.get(token, 0) + 0.5) / (self._df.get(token, 0) + 0.5))

    def keyword_scores(self, query: str) -> list[float]:
        q, out = tokenize(query), []
        for tf in self._tf:
            length, s = sum(tf.values()) or 1, 0.0
            for t in set(q):
                if t in tf:
                    s += self.idf(t) * tf[t] * 2.2 / (tf[t] + 1.2 * (0.25 + 0.75 * length / (self._avg or 1)))
            out.append(round(s, 6))
        return out

    def vector_scores(self, query: str) -> list[float]:
        qv = embed(query)
        return [round(cosine(qv, v), 6) for v in self._vectors]

    def coverage(self, query: str, chunk: dict) -> float:
        q = set(tokenize(query))
        total = sum(self.idf(t) for t in q)
        words = set(tokenize(f"{chunk.get('title', '')} {chunk.get('heading', '')} {chunk.get('text', '')}"))
        return round(sum(self.idf(t) for t in q if t in words) / total, 6) if total else 0.0

    def rerank(self, query: str, results: list[dict]) -> list[dict]:
        q = set(tokenize(query))
        total = sum(self.idf(t) for t in q) or 1.0

        def score(r: dict) -> float:
            head = set(tokenize(r.get("heading", "")))
            return self.coverage(query, r) + HEADING_WEIGHT * sum(self.idf(t) for t in q if t in head) / total
        return [dict(r, rerank_score=round(score(r), 6))
                for r in sorted(results, key=lambda r: (-score(r), results.index(r)))]


def citation_of(chunk: dict) -> dict:
    """{'doc_id', 'version', 'section', 'page'} — DCB's citation convention (page only for PDFs)."""
    return {"doc_id": chunk["doc_id"], "version": chunk["version"], "section": chunk["section"], "page": chunk.get("page")}


def source_line(chunk: dict) -> str:
    """'DCB-POL-KYC v4.0 §4 p.2 — Know Your Customer (KYC) Policy' — what an auditor needs to trace an answer."""
    page = f" p.{chunk['page']}" if chunk.get("page") else ""
    return f"{chunk['doc_id']} v{chunk['version']} §{chunk['section']}{page} — {chunk['title']}"


class AzureSearchIndex(SearchIndex):
    """Live SearchIndex backed by YOUR Azure AI Search index (run_week1.py --push-index pushes the chunks).

    Same interface as SearchIndex, so retrieval code is unchanged: keyword_scores = BM25 in Azure AI Search,
    vector_scores = vector query with text-embedding-3-small (cosine), rerank = the semantic ranker. With role set,
    every query also carries the server-side security filter (status current, role in access_roles).
    """

    def __init__(self, chunks: list[dict], role: str | None = None, excluded: set | None = None):
        super().__init__(chunks)
        self.role, self.excluded = role, set(excluded or ())

    def for_role(self, role: str) -> "AzureSearchIndex":
        view = AzureSearchIndex.__new__(AzureSearchIndex)
        view.__dict__.update(self.__dict__)
        view.role = role
        return view

    def _filter(self) -> str | None:
        from . import azure
        parts = [p for p in (azure.role_filter(self.role),) if p]
        if self.excluded:
            parts.append("not search.in(chunk_id, '" + "|".join(sorted(self.excluded)) + "', '|')")
        return " and ".join(parts) or None

    def _scores(self, body: dict, convert=lambda s: s) -> list[float]:
        from . import azure
        f = self._filter()
        hits = azure.search({**body, "select": "chunk_id", **({"filter": f} if f else {})})
        by_id = {h["chunk_id"]: convert(h["@search.score"]) for h in hits}
        return [round(by_id.get(c["id"], 0.0), 6) for c in self.chunks]

    def keyword_scores(self, query: str) -> list[float]:
        return self._scores({"search": query, "queryType": "simple", "searchFields": "text,heading,title", "top": 1000})

    def vector_scores(self, query: str) -> list[float]:
        from . import azure
        vector = azure.embed([query])[0]
        return self._scores({"vectorQueries": [{"kind": "vector", "vector": vector, "fields": "text_vector", "k": 50}],
                             "top": 50}, convert=lambda s: 2 - 1 / s if s else 0.0)   # @search.score → cosine

    def rerank(self, query: str, results: list[dict]) -> list[dict]:
        from . import azure
        if not results:
            return []
        try:
            ids = "|".join(r["id"] for r in results)
            hits = azure.search({"search": query, "queryType": "semantic",
                                 "semanticConfiguration": f"{azure.env('AZURE_SEARCH_INDEX', 'veriguard-m1')}-semantic",
                                 "filter": f"search.in(chunk_id, '{ids}', '|')", "select": "chunk_id",
                                 "top": len(results)})
            order = {h["chunk_id"]: h.get("@search.rerankerScore") or 0.0 for h in hits}
            return [dict(r, rerank_score=round(order.get(r["id"], 0.0), 6))
                    for r in sorted(results, key=lambda r: (-order.get(r["id"], 0.0), results.index(r)))]
        except azure.AzureError:
            return super().rerank(query, results)      # semantic ranker unavailable → local rerank


def make_index(chunks: list[dict], role: str | None = None) -> SearchIndex:
    """SearchIndex offline; AzureSearchIndex over your Azure AI Search index when VERIGUARD_MODE=live."""
    return AzureSearchIndex(chunks, role) if LIVE else SearchIndex(chunks)


def groundedness(answer: str, chunks: list[dict]) -> float:
    """Groundedness evaluator stand-in (1–5): share of the answer's content tokens found in the cited chunks."""
    body = (answer or "").split("Sources:")[0]
    toks = [t for t in tokenize(body) if not t.isdigit()]
    if not toks:
        return 1.0
    support = set(t for c in chunks for t in tokenize(f"{c.get('heading', '')} {c.get('text', '')}"))
    return round(1 + 4 * sum(t in support for t in toks) / len(toks), 2)


def expected_citations(item: dict) -> set[tuple[str, str, str]]:
    """Golden item → {(doc_id, version, section)}. 'DCB-MTH-CRR;DCB-SOP-TMI' / '1.2;3.0' / '2,3;5' expands to
    {('DCB-MTH-CRR','1.2','2'), ('DCB-MTH-CRR','1.2','3'), ('DCB-SOP-TMI','3.0','5')}. Empty for unanswerable."""
    docs = [d for d in (item.get("expected_doc_ids") or "").split(";") if d]
    versions = (item.get("expected_versions") or "").split(";")
    sections = (item.get("expected_sections") or "").split(";")
    return {(d, versions[i] if i < len(versions) else "", s.strip())
            for i, d in enumerate(docs) for s in (sections[i] if i < len(sections) else "").split(",") if s.strip()}


def load_golden() -> list[dict]:
    """datapack/04_evaluation/golden_dataset.jsonl — the 30 seeded questions plus the ones you author."""
    return load_jsonl(EVALUATION / "golden_dataset.jsonl")


# ============================================================================= Week 2 — core banking data (read-only)
CORE_SQL = "dcb_core.sql"          # the core-banking database ships as a SQL dump — no binary database in the project


def core_db_path() -> Path:
    """The SQLite file built from datapack/02_structured_data/dcb_core.sql — created once in the system temp folder
    (outside the project) and reused while the .sql is unchanged; a changed dump gets a fresh build."""
    sql_path = STRUCTURED / CORE_SQL
    sql = sql_path.read_bytes()
    target = Path(tempfile.gettempdir()) / f"veriguard-dcb-core-{hashlib.sha256(sql).hexdigest()[:16]}.sqlite"
    if not target.exists():
        building = target.with_name(f"{target.name}.{os.getpid()}.building")
        try:
            with sqlite3.connect(building) as conn:
                conn.executescript(sql.decode("utf-8"))
            conn.close()
            os.replace(building, target)              # atomic: parallel runs never see a half-built file
        finally:
            if building.exists():
                building.unlink()
    return target


def db() -> sqlite3.Connection:
    """Read-only connection to the core-banking database (datapack/02_structured_data/dcb_core.sql; rows behave like
    dicts). The SQL dump is loaded into SQLite on first use — see core_db_path()."""
    conn = sqlite3.connect(f"file:{core_db_path()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


POINTS = load_json(STRUCTURED / "risk_scoring_points.json")     # DCB-MTH-CRR §2, machine-readable
BANDS = (("High", 70), ("Medium", 40), ("Low", 0))               # DCB-MTH-CRR §3
SCORED_TYPOLOGIES = ("structuring", "layering", "mule", "round_tripping")   # 20 points each, max 40
TYPOLOGY_LABELS = {"structuring": "Structuring", "layering": "Layering via high-risk jurisdiction",
                   "mule": "Money mule", "round_tripping": "Round-tripping",
                   "dormant_reactivation": "Dormant account reactivation",
                   "unexplained_wealth_pep": "Unexplained wealth - PEP"}   # the names used in datapack/03_alerts labels
INDICATOR_TYPOLOGIES = ("dormant_reactivation", "unexplained_wealth_pep")   # reported, not scored
CTR_THRESHOLD = 1_000_000
REVIEW_DAYS = 90                                                 # DCB-SOP-TMI §2: 90 days of history
LEGIT_EVIDENCE = re.compile(r"sale deed|bonus letter|esop|gst returns|loan sanction|maturity|succession|"
                            r"employment contract", re.I)


def get_alert(alert_id: str) -> dict | None:
    """The alert from dcb_core.sql (alerts table), or from datapack/03_alerts/holdout_rehearsal.csv (rehearsal hold-out alerts)."""
    with db() as conn:
        row = conn.execute("select * from alerts where alert_id=?", (alert_id,)).fetchone()
    if row:
        return dict(row)
    path = ALERTS / "holdout_rehearsal.csv"
    if path.exists():
        return next((r for r in load_csv(path) if r["alert_id"] == alert_id), None)
    return None


def get_customer(customer_id: str) -> dict | None:
    """The raw KYC record — contains PII. Never send it to a model or a log; tools return masked views."""
    with db() as conn:
        row = conn.execute("select * from customers_kyc where customer_id=?", (customer_id,)).fetchone()
    return dict(row) if row else None


def get_account(account_id: str) -> dict | None:
    with db() as conn:
        row = conn.execute("select * from accounts where account_id=?", (account_id,)).fetchone()
    return dict(row) if row else None


def transactions(customer_id: str, start: str | None = None, end: str | None = None) -> list[dict]:
    """The customer's transactions with start <= txn_timestamp <= end (ISO strings), oldest first."""
    sql, args = "select * from transactions where customer_id=?", [customer_id]
    if start:
        sql, args = sql + " and txn_timestamp>=?", args + [start]
    if end:
        sql, args = sql + " and txn_timestamp<=?", args + [end]
    with db() as conn:
        return [dict(r) for r in conn.execute(sql + " order by txn_timestamp", args)]


def ts(row: dict) -> _dt.datetime:
    return _dt.datetime.fromisoformat(row["txn_timestamp"])


def review_transactions(alert: dict) -> list[dict]:
    """The REVIEW_DAYS of history up to the alert's trigger time (DCB-SOP-TMI §2)."""
    end = _dt.datetime.fromisoformat(alert["triggered_at"])
    return transactions(alert["customer_id"], (end - _dt.timedelta(days=REVIEW_DAYS)).isoformat(), alert["triggered_at"])


def velocity_anomaly(alert: dict) -> dict:
    """DCB-MTH-CRR §2: 30-day turnover > 3 × the 90-day baseline (baseline = the 90 days before the 30-day window,
    as a monthly average; windows end at the last transaction on or before the trigger)."""
    rows = transactions(alert["customer_id"], None, alert["triggered_at"])
    if not rows:
        return {"anomaly": False, "turnover_30d": 0.0, "baseline_monthly": 0.0}
    anchor = ts(rows[-1])
    window = sum(r["amount_inr"] for r in rows if anchor - _dt.timedelta(days=30) < ts(r) <= anchor)
    base = sum(r["amount_inr"] for r in rows
               if anchor - _dt.timedelta(days=120) < ts(r) <= anchor - _dt.timedelta(days=30)) / 3
    return {"anomaly": window > 3 * base, "turnover_30d": round(window, 2), "baseline_monthly": round(base, 2)}


def high_risk_jurisdictions(category: str = "HIGH_RISK") -> dict:
    """{code: name} — DCB-REG-HRJ. category 'INCREASED_MONITORING' lists the watch-only ones (e.g. Belmora)."""
    with db() as conn:
        return {r["code"]: r["name"] for r in conn.execute("select * from high_risk_jurisdictions where category=?",
                                                           (category,))}


def legit_explanation(customer: dict) -> str | None:
    """The documented legitimate explanation on file (DCB-SOP-TMI §3 mitigating evidence), or None."""
    docs = customer.get("documents_on_file") or ""
    return docs if LEGIT_EVIDENCE.search(docs) else None


def normalise_name(name: str) -> str:
    return " ".join(re.sub(r"[^a-z ]", " ", (name or "").lower()).split())


def related_parties(customer: dict) -> set[str]:
    """Normalised names of entities sharing a director with the customer (from the MCA note on file)."""
    m = re.search(r"common director with (.+)", customer.get("documents_on_file") or "", re.I)
    return {normalise_name(x) for x in re.split(r"\s+and\s+|,", m.group(1)) if x.strip()} if m else set()


def name_similarity(a: str, b: str) -> float:
    return round(SequenceMatcher(None, normalise_name(a), normalise_name(b)).ratio(), 3)


def watchlist(list_types: tuple = ("SANCTIONS", "INTERNAL_NEGATIVE")) -> list[dict]:
    """Watchlist entries of the given list types (PEP status comes from customers_kyc.pep_flag instead)."""
    with db() as conn:
        rows = [dict(r) for r in conn.execute("select * from watchlist")]
    return [r for r in rows if r["list_type"] in list_types]


def adverse_media_names() -> set[str]:
    """Normalised names with ADVERSE coverage (neutral 'no adverse content' items excluded)."""
    with db() as conn:
        return {normalise_name(r["entity_name"]) for r in conn.execute("select * from adverse_media")
                if "no adverse" not in (r["summary"] or "").lower()}


def mask_aadhaar(value: str | None) -> str | None:
    """DCB-STD-DCP §2: 'XXXX XXXX 1234'."""
    digits = re.sub(r"\D", "", value or "")
    return f"XXXX XXXX {digits[-4:]}" if len(digits) == 12 else value


def mask_pan(value: str | None) -> str | None:
    """DCB-STD-DCP §2: middle five masked — 'ABXXXXX34F'."""
    return f"{value[:2]}XXXXX{value[7:]}" if value and len(value) == 10 else value


def mask_account(value: str | None) -> str | None:
    """DCB-STD-DCP §2: last 4 digits only — 'XXXXXXXXXX8511'."""
    digits = re.sub(r"\D", "", value or "")
    return "X" * (len(digits) - 4) + digits[-4:] if len(digits) > 4 else value


def validate_json(obj, schema: dict, path: str = "$") -> list[str]:
    """Minimal JSON-schema validator (type, required, properties, additionalProperties, items, enum, const, pattern,
    minLength, minimum, maximum) —
    the stand-in for Pydantic models. Returns a list of error strings; [] means valid."""
    errors: list[str] = []
    types = {"object": dict, "array": list, "string": str, "integer": int, "number": (int, float), "boolean": bool}
    t = schema.get("type")
    if t and not (isinstance(obj, types[t]) and not (t in ("integer", "number") and isinstance(obj, bool))):
        return [f"{path}: expected {t}, got {type(obj).__name__}"]
    if "enum" in schema and obj not in schema["enum"]:
        errors.append(f"{path}: {obj!r} not in {schema['enum']}")
    if "const" in schema and obj != schema["const"]:
        errors.append(f"{path}: must be {schema['const']!r}")
    if isinstance(obj, str) and "pattern" in schema and not re.search(schema["pattern"], obj):
        errors.append(f"{path}: {obj!r} does not match {schema['pattern']}")
    if isinstance(obj, str) and len(obj) < schema.get("minLength", 0):
        errors.append(f"{path}: shorter than {schema['minLength']} characters")
    if isinstance(obj, (int, float)) and not isinstance(obj, bool):
        if "minimum" in schema and obj < schema["minimum"]:
            errors.append(f"{path}: {obj} < {schema['minimum']}")
        if "maximum" in schema and obj > schema["maximum"]:
            errors.append(f"{path}: {obj} > {schema['maximum']}")
    if isinstance(obj, dict):
        errors += [f"{path}: missing '{k}'" for k in schema.get("required", []) if k not in obj]
        if schema.get("additionalProperties") is False:
            errors += [f"{path}: unexpected '{k}'" for k in obj if k not in schema.get("properties", {})]
        for k, sub in schema.get("properties", {}).items():
            if k in obj:
                errors += validate_json(obj[k], sub, f"{path}.{k}")
    if isinstance(obj, list) and "items" in schema:
        for i, item in enumerate(obj):
            errors += validate_json(item, schema["items"], f"{path}[{i}]")
    return errors


def band_of(score: int) -> str:
    return next(name for name, low in BANDS if score >= low)


# ============================================================================= Week 3 — identity, guardrails, audit
TENANT_ID = os.getenv("AZURE_TENANT_ID", "dcb-tenant-0001") if LIVE else "dcb-tenant-0001"
API_AUDIENCE = os.getenv("VERIGUARD_API_AUDIENCE", "api://veriguard-api") if LIVE else "api://veriguard-api"
GROUP_ROLES = {   # Entra ID security groups (object ids in the token's 'groups' claim) → VeriGuard app roles
    "grp-aml-analysts": "Analyst", "grp-aml-investigators": "Investigator", "grp-internal-audit": "Auditor",
    "grp-principal-officer": "PrincipalOfficer", "grp-platform-admins": "Admin"}
if LIVE:   # real tokens carry group OBJECT IDs: ENTRA_GROUP_ANALYST=<object id> etc. in .env
    GROUP_ROLES.update({os.environ[f"ENTRA_GROUP_{r.upper()}"]: r for r in ("Analyst", "Investigator", "Auditor",
                                                                             "PrincipalOfficer", "Admin")
                        if os.getenv(f"ENTRA_GROUP_{r.upper()}")})


def tool_permissions() -> dict:
    """datapack/05_security/tool_permissions.csv as {tool: {role: 'Y' | 'N' | 'Y (…)'}} plus 'notes'."""
    return {r["tool"]: {k: v.strip() for k, v in r.items() if k != "tool"} for r in load_csv(SECURITY / "tool_permissions.csv")}


PII_LABELS = ("AADHAAR", "PAN", "ACCOUNT_NUMBER", "PHONE", "EMAIL", "ADDRESS")
INJECTION_PATTERNS = [   # Prompt Shields stand-in — direct injection and jailbreak markers
    r"\bignore\s+(all\s+|any\s+|the\s+|your\s+)?(previous\s+|prior\s+|above\s+)?(instructions|rules|prompts?)",
    r"\bdisregard\s+(all\s+|the\s+|your\s+)?(previous\s+|prior\s+)?(instructions|rules|policy|policies|checks)",
    r"\b(reveal|show|print|repeat)\b[^.?!]*\bsystem\s+prompt", r"\byou are now\b", r"\bdeveloper mode\b",
    r"\bjailbreak\b", r"\bDAN\b", r"\bdo anything now\b"]
BLOCKLIST = [   # Content Safety custom blocklist — tipping-off (DCB-POL-AML) and evading controls
    r"\b(tell|inform|notify|warn|let)\b[^.?!]*\b(customer|client|account holder)\b[^.?!]*\b(str|report\w*|investigat\w*|suspicio\w*)",
    r"\b(avoid|evade|beat|get around)\b[^.?!]*\b(detection|monitoring|reporting|threshold|ctr)\b",
]
INDIRECT_INJECTION = re.compile(r"note to (an? )?(ai|automated) (assistants?|agents?|systems?)|do not mention this "
                                r"instruction|ignore (previous|prior) (access|masking) rules", re.I)
GENESIS = "0" * 64


MASK_ARTEFACTS = re.compile(r"XXXX XXXX \d{4}|\b[A-Z]{2}XXXXX[A-Z0-9]{3}\b|\bX{4,}\d{4}\b|\[REDACTED\]")


def retrieval_text(masked: str) -> str:
    """The masked prompt without its mask placeholders — what the search index should see (masks are not evidence)."""
    return " ".join(MASK_ARTEFACTS.sub(" ", masked or "").split())


def prompt_shield_attack(text: str) -> bool:
    """Prompt Shields for the USER prompt: offline the INJECTION_PATTERNS; live Azure AI Content Safety
    (jailbreak detection) as well — either one detecting an attack blocks."""
    if any(re.search(p, text or "", re.I) for p in INJECTION_PATTERNS):
        return True
    if LIVE:
        from . import azure
        return azure.prompt_shield(text)["user_attack"]
    return False


def looks_like_injection(text: str) -> bool:
    """Prompt Shields for a retrieved DOCUMENT: offline a pattern check; live Content Safety's document-attack
    detection as well. True when the document carries instructions aimed at AI systems."""
    if INDIRECT_INJECTION.search(text or ""):
        return True
    if LIVE:
        from . import azure
        return any(azure.prompt_shield("Summarise this document.", [text])["document_attacks"])
    return False


def entry_hash(entry: dict) -> str:
    """SHA-256 of an audit entry without its own 'hash' field (keys sorted)."""
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False, default=str).encode()).hexdigest()


def dev_principal(role: str, user_id: str | None = None) -> dict:
    """A principal for local development — the same shape principal_from_claims returns."""
    return {"user_id": user_id or f"dev-{role.lower()}", "name": role, "roles": [role]}


def index_without(index: SearchIndex, chunk_ids: set) -> SearchIndex:
    """A new SearchIndex without the given chunks (quarantine the poisoned section; the rest stays usable).
    Live, the exclusion is also pushed into every Azure AI Search query as a filter."""
    kept = [c for c in index.chunks if c.get("id") not in chunk_ids]
    if isinstance(index, AzureSearchIndex):
        return AzureSearchIndex(kept, index.role, index.excluded | set(chunk_ids))
    return SearchIndex(kept)


# ============================================================================= Week 4 — reporting and operations
PRICE_INPUT_PER_1K = 0.0004
PRICE_OUTPUT_PER_1K = 0.0016
STR_DUE_WORKING_DAYS = 7         # DCB-RD-PMLA §2
APPROVAL_THRESHOLD = 70          # DCB-SOP-TMI §5
LIFECYCLE = ("New", "In Triage", "Under Investigation", "Escalated to Principal Officer", "Closed - No Further Action",
             "Closed - STR Filed")   # DCB-SOP-TMI §1


def add_working_days(start: str, days: int) -> str:
    """'2026-09-14' + 7 working days (Mon–Fri; bank holidays not modelled) → '2026-09-23'."""
    current = _dt.date.fromisoformat(str(start)[:10])
    while days > 0:
        current += _dt.timedelta(days=1)
        if current.weekday() < 5:
            days -= 1
    return current.isoformat()


def load_labels(name: str) -> list[dict]:
    """datapack/03_alerts/<name>.csv — m2_test_alerts_labels or error_analysis_labels."""
    return load_csv(ALERTS / f"{name}.csv")
