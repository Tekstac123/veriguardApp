# VeriGuard Capstone — Learner Data Pack
**Deccan Commonwealth Bank (DCB)** · fictional · all data is synthetic

> Every person, company, account, identifier and jurisdiction in this pack is fictional. Aadhaar/PAN-style values are randomly generated. Regulatory digests are simplified training summaries, not legal text.

## Contents and when you need them

| Folder | What's inside | First used |
|---|---|---|
| `01_documents/` | 22 documents (12 PDF, 10 Markdown) + `corpus_manifest.csv` (version, status, classification, access roles) | Wk 1–2 |
| `02_structured_data/` | Customers/KYC, accounts, transactions, watchlist, adverse media, jurisdictions, branches — as CSV, SQLite (`dcb_core.sql`) and `schema.sql` | Wk 3 |
| `03_alerts/` | `alerts_queue.csv` (33 alerts), M2 test labels (3), error-analysis labels (30) | Wk 3, Wk 5 |
| `04_evaluation/` | Golden dataset seed (30 Q&A with expected citations) | Wk 2 |
| `05_security/` | Access matrix, tool permissions, 20 cross-role tests, 40-prompt attack set, 20 PII masking tests | Wk 4 |
| `06_templates/` | JSON schemas for the case file and STR draft | Wk 3, Wk 5 |

## Documents
- **Superseded versions are included on purpose** (`DCB-POL-KYC` v3.2 and `DCB-POL-RET` v1.0). Your system must answer from the current version and say so when a superseded version exists.
- **Classifications:** Internal, Confidential (3 audit reports), Board-Restricted (1). See `05_security/access_matrix.csv`.
- **Treat every document as untrusted input.** At least one document contains content that should never be followed.

## Structured data (period: 1 Jun – 15 Sep 2026)
| File | Rows | Notes |
|---|---|---|
| `customers_kyc.csv` | 303 | Contains synthetic PII (Aadhaar, PAN, phone, email, address) — mask before any model call |
| `accounts.csv` | 303 | |
| `transactions.csv` | 7,289 | Channels: CASH_DEPOSIT, NEFT, RTGS, IMPS, UPI, ATM, SWIFT_IN/OUT |
| `watchlist.csv` | 96 | SANCTIONS, PEP, INTERNAL_NEGATIVE |
| `adverse_media.csv` | 7 | Synthetic news items |
| `high_risk_jurisdictions.csv` | 7 | Matches `DCB-REG-HRJ` |
| `risk_scoring_points.json` | – | Factor points from `DCB-MTH-CRR` s2 (machine-readable) |

**Load into Azure SQL:** run `schema.sql`, then bulk-insert the CSVs. For local development, use `dcb_core.sql` (SQLite, same schema).

## Alerts and labels
- `m2_test_alerts_labels.csv` — the 3 alerts your M2 system must disposition correctly (ALR-2026-0417, -0452, -0466). Includes the expected risk score, band and factors.
- `error_analysis_labels.csv` — 30 labelled alerts (12 true positives, 18 false positives) for Week 5 error analysis.
- The M4 panel will use **unseen hold-out alerts**. Their transactions are already in the data; the alerts are not.

## Security test assets (Week 4)
- `attack_set.jsonl` — 40 prompts across 7 categories, each with an expected safe behaviour and severity. Add at least 10 of your own.
- `pii_test_set.jsonl` — 20 texts with expected masks. PII formats vary on purpose.
- `access_tests.csv` — 20 role × document/tool tests (expected ALLOW/DENY).

## Conventions
- **Citations:** `doc_id` + `version` + `section` (plus page for PDFs).
- **Masking rules** (per `DCB-STD-DCP` s2):
  - Aadhaar → `XXXX XXXX 1234`
  - PAN → `ABXXXXX34F`
  - Account number → last 4 digits only
  - Phone, email, address → `[REDACTED]`
- **Roles:** Analyst, Investigator, Auditor, PrincipalOfficer, Admin.
