"""VeriGuard Week 1 Q&A app — try YOUR pipeline in the browser (PROVIDED, do not modify).

    python -m uvicorn api.week1_app:app --reload --port 8000

    http://127.0.0.1:8000/          ask a question as a role (simple page)
    http://127.0.0.1:8000/docs      Swagger UI for the JSON endpoints
    GET  /health                    mode, LLM provider, model, chunk count
    POST /ask     {"role": "Analyst", "question": "..."}           → answer_question(...)
    GET  /search?q=...&role=Analyst&mode=hybrid_rerank&k=5          → hybrid_search(...)

Uses your veriguard/ingestion.py and veriguard/retrieval.py. Answer text comes from the LLM gateway when
VERIGUARD_LLM=gateway and OPENAI_API_KEY is in .env; citations, trimming and declines come from your code.
Local development only — there is no sign-in here (that is Week 3); the role is whatever you choose.
"""
from __future__ import annotations

import html
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI, HTTPException  # noqa: E402
from fastapi.responses import HTMLResponse  # noqa: E402
from pydantic import BaseModel  # noqa: E402

from veriguard import common  # noqa: E402

app = FastAPI(title="VeriGuard · Week 1 grounded Q&A", version="1.0")
STATE: dict = {}


class Ask(BaseModel):
    role: str = "Analyst"
    question: str


def index():
    if "index" not in STATE:
        from veriguard.ingestion import build_corpus
        try:
            STATE["index"] = common.make_index(build_corpus())
        except NotImplementedError as exc:
            raise HTTPException(501, f"Task 1 not finished yet: {exc}") from exc
    return STATE["index"]


def llm_info() -> dict:
    info = {"provider": common.LLM_PROVIDER}
    if common.LLM_PROVIDER == "gateway":
        from veriguard import llm
        s = llm.settings()
        info.update(model=s["model"], base_url=s["base_url"], key_set=s["key_set"],
                    last_call={k: llm.LAST[k] for k in ("ok", "kind", "input_tokens", "output_tokens")})
    return info


@app.get("/health")
def health():
    return {"mode": common.MODE, "llm": llm_info(), "chunks": len(index().chunks)}


@app.post("/ask")
def ask(body: Ask):
    from veriguard.retrieval import answer_question
    try:
        return {"role": body.role, "question": body.question, **answer_question(index(), body.question, body.role),
                "llm": llm_info()}
    except NotImplementedError as exc:
        raise HTTPException(501, f"Task 2 not finished yet: {exc}") from exc
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc


@app.get("/search")
def search(q: str, role: str = "Analyst", mode: str = "hybrid_rerank", k: int = 5):
    from veriguard.retrieval import hybrid_search
    try:
        hits = hybrid_search(index(), q, role, k, mode)
    except NotImplementedError as exc:
        raise HTTPException(501, f"Task 2 not finished yet: {exc}") from exc
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    keep = ("id", "doc_id", "version", "section", "page", "classification", "status", "score", "keyword_score",
            "vector_score", "rerank_score", "heading")
    return {"query": q, "role": role, "mode": mode, "results": [{k2: h.get(k2) for k2 in keep} for h in hits]}


PAGE = """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,
initial-scale=1"><title>VeriGuard · Week 1</title><style>
body{font-family:Arial,sans-serif;max-width:860px;margin:24px auto;padding:0 16px;color:#222}
h1{font-family:Georgia,serif}textarea{width:100%;height:70px;font-size:15px}select,button{font-size:15px;padding:6px 10px}
button{background:#0a0a0a;color:#9ac220;border:1px solid #9ac220;cursor:pointer}
pre{background:#0a0a0a;color:#ddd;padding:14px;white-space:pre-wrap;border:1px solid #9ac220}
.meta{color:#666;font-size:13px}</style></head><body>
<h1>VeriGuard · Week 1 grounded Q&amp;A</h1><p class="meta">LLM: __LLM__ · mode: __MODE__</p>
<label>Role <select id="role">__ROLES__</select></label><br><br>
<textarea id="q">What single cash deposit amount triggers an internal monitoring alert at DCB?</textarea><br><br>
<button onclick="go()">Ask VeriGuard</button><pre id="out">…</pre>
<script>
async function go(){const out=document.getElementById('out');out.textContent='Thinking…';
try{const r=await fetch('/ask',{method:'POST',headers:{'Content-Type':'application/json'},
body:JSON.stringify({role:document.getElementById('role').value,question:document.getElementById('q').value})});
const j=await r.json();out.textContent=r.ok?(j.answer+'\\n\\nrefused: '+j.refused+'\\ncitations: '+
JSON.stringify(j.citations)):('Error '+r.status+': '+(j.detail||JSON.stringify(j)));}catch(e){out.textContent=String(e);}}
</script></body></html>"""


@app.get("/", response_class=HTMLResponse)
def home():
    info = llm_info()
    label = (f"{info.get('model')} via the LLM gateway" if info["provider"] == "gateway" and info.get("key_set")
             else info["provider"])
    roles = "".join(f"<option>{r}</option>" for r in common.ROLES)
    return PAGE.replace("__LLM__", html.escape(label)).replace("__MODE__", common.MODE).replace("__ROLES__", roles)
