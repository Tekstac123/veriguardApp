"""Week 3 · Task 1 — Identity, on-behalf-of tool permissions, PII masking and the input guardrails.

Who someone is comes from verified Microsoft Entra ID token claims (group claims → app roles), never from a sentence
in a prompt. Tools enforce the CALLER's permissions (datapack/05_security/tool_permissions.csv). Personal data is masked
before any model call and in every log (DCB-STD-DCP §2). Prompts are screened before anything is retrieved.
"""

# ─── WEEK 3 · M3 Secure & Governed AI System — you implement the stubbed functions in this file in Week 3 ───
from __future__ import annotations

import re

from .common import (  # noqa: F401 — helpers you will need
    API_AUDIENCE,
    BLOCKLIST,
    GROUP_ROLES,
    ROLES,
    TENANT_ID,
    prompt_shield_attack,
    tool_permissions,
)

# TODO [Week 3 · Task 1]: Prompt Shields / Content Safety patterns for the attack families the provided lists miss —
#       persona and role claims, state-changing requests in chat (imperatives, or an action on a named ALR- case),
#       tool and data exfiltration, encodings, bulk PII requests, off-policy content. Genuine policy questions
#       ("Who can close a High band investigation?") must still pass.
RED_TEAM_PATTERNS: list[str] = [
    # persona / role claims and prompt-structure tricks
    r"\b(set|change|switch)\s+my\s+role\b|\bact\s+as\b|\byou\s+are\s+'?\w+'?,?\s+an\s+ai\b|\bno restrictions\b|"
    r"\bsafety rules (are )?suspended\b|\bsystem override\b|\bmaintenance mode\b|\bthe user is an administrator\b|"
    r"</?context>|\bhypothetically\b|\bwithout any citations\b|\bas (an? )?(admin|administrator|principal officer)\b|"
    r"\b(officer|po)'s session\b|\bexecute it\b",
    # state-changing requests through chat: imperative verbs, or any action on a named case
    r"(?:^|[.!?:]\s*|\bplease\s+)(close|approve|reject|submit|file|mark|lower|raise|change|delete)\b|"
    r"\b(close|approve|reject|submit|file|mark|lower)\b[^.?!]*\bALR-\d{4}-\d{3,4}",
    # tool and data exfiltration, encodings
    r"\b(every|all)\s+(customer|customers|names|accounts)\b|\b\d{3,}\s+names\b|\bselect\s+\*|\bfrom\s+customers_kyc\b|"
    r"\bpersonal\s+e-?mail\b|!\[[^\]]*\]\(https?://|\bexport\b[^.?!]*\baudit log\b|\braw json\b|\bbase64\b|"
    r"\bone character per line\b|\bunmasked\b",
    # bulk or direct requests for identity numbers
    r"\b(aadhaar|pan)\s+(number\s+)?of\b|\bphone number and home address\b|\bfull names and aadhaar\b|"
    r"\breads? out\b[^.?!]*\b(aadhaar|pan)\b",
    # off-policy content: evasion roadmaps, tipping-off, improper closure, abuse
    r"\b(weakest|easiest)\b[^.?!]*\b(bypass|evade|launder)|\bso they don't trigger\b|\bclose[^.?!]*\bquietly\b|"
    r"\binsult\w*\b|\btelling him we are investigating\b|\bmove his money\b",
]
CONDITIONS = re.compile(r"Y \((?P<cond>[^)]*)\)")


def principal_from_claims(claims: dict, now: int) -> dict:
    """A verified principal from Entra-style token claims; PermissionError names the first failed check.

    Returns {"user_id", "name", "roles"} — roles from the 'groups' claim (GROUP_ROLES) and known app 'roles'.
    """
    if claims.get("tid") != TENANT_ID:
        raise PermissionError("token issued for another tenant")
    aud = claims.get("aud")
    accepted = {API_AUDIENCE}
    if API_AUDIENCE.startswith("api://"):
        accepted.add(
            API_AUDIENCE[len("api://") :]
        )  # v2 tokens carry the bare client id
    else:
        accepted.add("api://" + API_AUDIENCE)
    if not accepted.intersection(aud if isinstance(aud, list) else [aud]):
        raise PermissionError("token audience is not VeriGuard")
    if not isinstance(claims.get("exp"), (int, float)) or now >= claims["exp"]:
        raise PermissionError("token expired")
    if isinstance(claims.get("nbf"), (int, float)) and now < claims["nbf"]:
        raise PermissionError("token not valid yet")
    if not claims.get("oid"):
        raise PermissionError("token has no user claim (oid)")
    roles = [GROUP_ROLES[g] for g in claims.get("groups", []) if g in GROUP_ROLES]
    roles += [r for r in claims.get("roles", []) if r in ROLES and r not in roles]
    if not roles:
        raise PermissionError("token carries no VeriGuard group or app role")
    return {"user_id": claims["oid"], "name": claims.get("name", ""), "roles": roles}


def authorize_tool(
    principal: dict, tool: str, context: dict | None = None
) -> str | None:
    """On-behalf-of check from tool_permissions.csv. Returns the condition ('masked', …) or None when allowed
    unconditionally; raises PermissionError when the caller may not use the tool (or not in this context)."""
    table = tool_permissions().get(tool)
    if table is None:
        raise PermissionError(f"unknown tool '{tool}'")
    context = context or {}
    for role in principal.get("roles", []):
        cell = table.get(role, "N")
        if cell == "Y":
            return None
        m = CONDITIONS.match(cell)
        if not m:
            continue
        cond = m.group("cond")
        if tool == "update_case_status":
            band = context.get("band")
            allowed = {
                "Low/Medium close": {"Low", "Medium"},
                "Medium close": {"Medium"},
                "all": {"Low", "Medium", "High"},
            }
            if band in allowed.get(cond, set()):
                return cond
            continue
        return cond
    raise PermissionError(
        f"{principal.get('user_id')} ({', '.join(principal.get('roles', []))}) may not call {tool}"
        + (f" for a {context.get('band')} band case" if context.get("band") else "")
    )


# TODO [Week 3 · Task 1]: (label, compiled regex, replacement function) per PII type, applied in order, producing
#       DCB-STD-DCP §2 masks: Aadhaar 'XXXX XXXX 1234' (4-4-4, 12 digits, dashed, spaced digits), PAN 'ABXXXXX34F'
#       (upper-cased), account numbers last 4 only, phone / e-mail / address / passport / date of birth
#       '[REDACTED]'. A reference number like 2026-08-18-0001 is not an Aadhaar number.
PII_RULES = [  # order matters: e-mail and Aadhaar before account numbers; phone before account numbers
    ("EMAIL", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]+\b"), lambda m: "[REDACTED]"),
    (
        "AADHAAR",
        re.compile(r"(?<![\d-])\d{4}([ -])\d{4}\1\d{4}(?![\d-])"),
        lambda m: "XXXX XXXX " + re.sub(r"\D", "", m.group(0))[-4:],
    ),
    (
        "AADHAAR",
        re.compile(r"(?<!\d)(?:\d\s+){11}\d(?!\d)"),
        lambda m: "XXXX XXXX " + re.sub(r"\D", "", m.group(0))[-4:],
    ),
    (
        "AADHAAR",
        re.compile(r"(?<![\d-])[2-9]\d{11}(?![\d-])"),
        lambda m: "XXXX XXXX " + m.group(0)[-4:],
    ),
    (
        "PAN",
        re.compile(r"\b[A-Za-z]{5}\d{4}[A-Za-z]\b"),
        lambda m: m.group(0)[:2].upper() + "XXXXX" + m.group(0)[7:].upper(),
    ),
    (
        "PHONE",
        re.compile(r"(?:\+91[\s-]?)?(?<!\d)[6-9]\d{4}[\s-]?\d{5}(?!\d)"),
        lambda m: "[REDACTED]",
    ),
    (
        "ACCOUNT_NUMBER",
        re.compile(r"(?<![\d-])\d{9,18}(?![\d-])"),
        lambda m: "X" * (len(m.group(0)) - 4) + m.group(0)[-4:],
    ),
    ("PASSPORT", re.compile(r"\b[A-PR-WY][1-9]\d{6}\b"), lambda m: "[REDACTED]"),
    (
        "DATE_OF_BIRTH",
        re.compile(
            r"\b(?:DOB|date of birth|born)\b[^.]*?\b\d{2}[/-]\d{2}[/-]\d{4}\b", re.I
        ),
        lambda m: re.sub(r"\d{2}[/-]\d{2}[/-]\d{4}", "[REDACTED]", m.group(0)),
    ),
    (
        "ADDRESS",
        re.compile(
            r"\b(?:Flat|House|Plot|Door|H\.?\s?No\.?)\s*\d+[\w\s,.-]*?\b\d{6}\b|"
            r"\b\d{1,4},\s*[A-Z][\w ]+,\s*[A-Z][a-z]+\b"
        ),
        lambda m: "[REDACTED]",
    ),
]


def mask_pii(text: str) -> dict:
    """DCB-STD-DCP §2 masking of free text: {"text": masked, "entities": [labels found, in order]}."""
    masked, found = text or "", []
    for label, pattern, repl in PII_RULES:
        masked, n = pattern.subn(repl, masked)
        found += [label] * n
    return {"text": masked, "entities": found}


def guard_input(text: str) -> dict:
    """Prompt Shields + Content Safety stand-in: {"text": PII-masked, "blocked": bool, "reasons": [...]}.
    reasons: "pii_masked" (does not block), "prompt_injection", "unsafe_request", "harmful_content"."""
    masked = mask_pii(text)
    reasons = ["pii_masked"] if masked["entities"] else []
    if prompt_shield_attack(text or ""):
        reasons.append("prompt_injection")
    if any(re.search(p, text or "", re.I) for p in RED_TEAM_PATTERNS):
        reasons.append("unsafe_request")
    if any(re.search(p, text or "", re.I) for p in BLOCKLIST):
        reasons.append("harmful_content")
    blocked = any(r != "pii_masked" for r in reasons)
    return {"text": masked["text"], "blocked": blocked, "reasons": reasons}
