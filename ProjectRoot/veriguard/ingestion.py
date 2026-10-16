"""Week 1 · Task 1 — Document processing: page-aware, clause-level chunks that carry the manifest's metadata.

Reads DCB's corpus in both formats (PDF and Markdown), splits each document at its numbered sections, and
attaches the metadata every later control depends on: version and status (superseded traps), classification and
access_roles (security trimming), section and page (citations an auditor can follow).

Find your work with:  grep -n "TODO" veriguard/ingestion.py
Check it with:        python check_week1.py --task 1
"""

from __future__ import annotations

from pathlib import Path

from .common import (  # noqa: F401 — helpers you will need
    DOCS,
    PAGE_NOISE,
    SECTION_HEADING,
    doc_type_of,
    document_lines,
    load_manifest,
    split_words,
)

# ─── WEEK 1 · L0 + M1 Grounded Financial Intelligence — you implement the stubbed functions in this file in Week 1 ───


def extract_sections(path: Path, title: str) -> list[dict]:
    """The numbered sections of one document: [{"section", "heading", "page", "text"}] in document order."""
    path = Path(path)
    sections: list[dict] = []
    for page, line, styled in document_lines(path):
        if line == title or PAGE_NOISE.match(line):
            continue
        m = SECTION_HEADING.match(line)
        if m and (styled or path.suffix == ".pdf"):
            sections.append(
                {
                    "section": m.group("section"),
                    "heading": m.group("heading").strip(),
                    "page": page,
                    "lines": [],
                }
            )
        elif sections:
            sections[-1]["lines"].append(line)

    return [
        {
            "section": s["section"],
            "heading": s["heading"],
            "page": s["page"],
            "text": " ".join(s["lines"]),
        }
        for s in sections
    ]


def build_chunks(
    meta: dict, sections: list[dict], max_words: int = 120, overlap: int = 20
) -> list[dict]:
    """Chunk dicts for one document version: one per section (long sections windowed), manifest metadata on each.

    Keys: id ("<doc_id>:<version>:<section>:<chunk_no>"), doc_id, title, doc_type, version, status (lower-case),
    effective_date, superseded_by, classification, access_roles (list), source, section, heading, page, chunk_no,
    text ("<heading>. <window>").
    """
    common = {
        "doc_id": meta["doc_id"],
        "title": meta["title"],
        "doc_type": doc_type_of(meta["doc_id"]),
        "version": meta["version"],
        "status": meta["status"].lower(),
        "effective_date": meta["effective_date"],
        "superseded_by": meta.get("superseded_by") or None,
        "classification": meta["classification"],
        "access_roles": [
            r.strip() for r in meta["access_roles"].split(";") if r.strip()
        ],
        "source": meta["file"],
    }
    chunks = []
    for s in sections:
        for n, window in enumerate(split_words(s["text"], max_words, overlap) or [""]):
            chunks.append(
                {
                    **common,
                    "id": f"{meta['doc_id']}:{meta['version']}:{s['section']}:{n}",
                    "section": s["section"],
                    "heading": s["heading"],
                    "page": s["page"],
                    "chunk_no": n,
                    "text": f"{s['heading']}. {window}".strip(),
                }
            )
    return chunks


# ----------------------------------------------------------------------------- provided
def build_corpus() -> list[dict]:
    """PROVIDED — every chunk of every document version listed in the manifest (superseded versions included)."""
    chunks: list[dict] = []
    for meta in load_manifest():
        chunks.extend(
            build_chunks(meta, extract_sections(DOCS / meta["file"], meta["title"]))
        )
    return chunks
