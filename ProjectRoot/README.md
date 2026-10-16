# VeriGuard — complete learner project, all four weeks (reference)

The full ProjectRoot at the end of the programme with every graded function still a stub. Each week's lab ships the subset up to that week; your own code carries forward week to week.

| File | Week | Functions you implement |
|---|---|---|
| `.env` (from `.env.example`) | Week 1 | Task 0 — `OPENAI_API_KEY`, `OPENAI_BASE_URL`, `VERIGUARD_LLM=gateway` (LLM gateway) |
| `veriguard/ingestion.py` | Week 1 | `extract_sections`, `build_chunks` |
| `veriguard/retrieval.py` | Week 1 | `is_allowed`, `hybrid_search`, `answer_question`, `evaluate_qa` |
| `veriguard/tools.py` | Week 2 | `detect_typologies`, `screen_customer`, `compute_risk_score`, `call_tool` |
| `veriguard/agents.py` | Week 2 | `compliance_investigator`, `investigate`, `decide` |
| `veriguard/security.py` | Week 3 | `principal_from_claims`, `authorize_tool`, `mask_pii`, `guard_input` |
| `veriguard/governance.py` | Week 3 | `verify_chain`, `secure_ask`, `secure_tool_call`, `quality_gate` |
| `veriguard/reporting.py` | Week 4 | `draft_str`, `explain_case`, `compute_dashboard` |
| `veriguard/operations.py` | Week 4 | `trace_step`, `BudgetGuard.allow`, `BudgetGuard.charge`, `BudgetGuard.remaining`, `error_analysis` |

Also: `RED_TEAM_PATTERNS` and `PII_RULES` in `veriguard/security.py` (Week 3); at least 10 authored questions in `datapack/04_evaluation/golden_dataset.jsonl` (Week 1) and 10 authored attacks in `datapack/05_security/attack_set.jsonl` (Week 3).

Provided: `veriguard/common.py`, `veriguard/llm.py` (LLM gateway client), `check_week1.py`, `api/week1_app.py`, `veriguard/livecheck.py`, the official data pack in `datapack/`, `run_week1.py` … `run_week4.py`, `capstone_demo.py`, `docs/` templates.
